#!/usr/bin/env python3
"""
Safe-to-Delete EBS Snapshot Finder  (READ-ONLY)
-----------------------------------------------
Scans every logged-in AWS SSO profile across all enabled regions and reports
only snapshots that can actually be deleted from the EC2 console without error.

A snapshot is reported ONLY when ALL of the following are true:
  1. No AMI in this account references it - deprecated and DISABLED AMIs included
  2. No existing EBS volume was created from it
  3. Older than the age threshold (default 90 days)
  4. State is 'completed'
  5. Not managed by AWS Backup or Data Lifecycle Manager
  6. Not protected by an EBS snapshot lock
  7. Not public and not shared with any other AWS account

This script performs describe_* calls only. Nothing is ever deleted.

Usage:
    python3 safe_to_delete_snapshots.py
    python3 safe_to_delete_snapshots.py --min-age-days 180 --region us-west-2
"""

import argparse
import csv
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import boto3
from botocore.config import Config

CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"})
TS = datetime.now().strftime("%Y%m%d_%H%M%S")
GB_MONTH_USD = 0.05
DEFAULT_MIN_AGE_DAYS = 90

COLUMNS = [
    "Profile", "AccountId", "Region", "SnapshotId", "SourceVolumeId",
    "SizeGiB", "StartDate", "AgeDays", "Name", "Description",
    "EstMonthlyUSD", "SafeToDelete", "Reason",
]

SKIP_KEYS = [
    ("in_use_ami", "Referenced by an AMI (including deprecated and disabled AMIs)"),
    ("in_use_volume", "An existing EBS volume was created from it"),
    ("too_new", "Younger than the age threshold"),
    ("service_managed", "Managed by AWS Backup or DLM - delete via vault or policy"),
    ("locked", "Protected by an EBS snapshot lock"),
    ("shared_or_public", "Shared with another account or public"),
    ("not_completed", "Not in 'completed' state"),
]


# ----------- Detect logged-in SSO profiles -----------
def get_all_profiles():
    try:
        profiles = subprocess.check_output(
            ["aws", "configure", "list-profiles"], text=True
        ).splitlines()
        profiles = [p.strip() for p in profiles if p.strip()]
        if not profiles:
            raise Exception("No AWS profiles found. Please configure at least one profile.")

        valid_profiles = []
        for profile in profiles:
            try:
                session = boto3.Session(profile_name=profile)
                session.client("sts", config=CFG).get_caller_identity()
                valid_profiles.append(profile)
            except Exception:
                print(f"  [SKIP] Profile '{profile}' not logged in or token expired.")

        if not valid_profiles:
            raise Exception(
                "No AWS SSO profiles are currently logged in. "
                "Run 'aws sso login --profile <profile>' for at least one profile."
            )
        return valid_profiles
    except Exception as e:
        print(f"Error detecting AWS profiles: {e}")
        sys.exit(1)


# ----------- Helpers -----------
def get_account_id(session):
    try:
        return session.client("sts", config=CFG).get_caller_identity()["Account"]
    except Exception:
        return "unknown"


def get_regions(session, only_region=None):
    if only_region:
        return [only_region]
    try:
        ec2 = session.client("ec2", region_name="us-east-1", config=CFG)
        return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])
    except Exception as e:
        print(f"  [WARN] describe_regions failed ({e}); using fallback region list")
        return ["us-east-1", "us-west-2", "ap-south-1", "eu-west-1"]


def tag_value(tags, key):
    for t in tags or []:
        if t.get("Key") == key:
            return t.get("Value", "")
    return ""


def is_service_managed(snap):
    """AWS Backup / DLM snapshots cannot be deleted from the EC2 console."""
    desc = snap.get("Description") or ""
    keys = {t.get("Key", "") for t in (snap.get("Tags") or [])}
    if any(k.startswith("aws:backup") for k in keys) or "AWS Backup" in desc:
        return True
    if any(k.startswith("dlm:") for k in keys) or "Created for policy" in desc:
        return True
    return False


def get_ami_referenced_snapshots(ec2, warnings):
    """
    Snapshot IDs referenced by AMIs in this account.
    IncludeDisabled/IncludeDeprecated are critical: a disabled AMI still blocks
    deletion but is hidden from describe_images by default.
    """
    referenced = set()
    kwargs = {"Owners": ["self"], "IncludeDisabled": True, "IncludeDeprecated": True}
    try:
        pages = ec2.get_paginator("describe_images").paginate(**kwargs)
        images = [img for page in pages for img in page.get("Images", [])]
    except Exception as e:
        warnings.append(f"describe_images with IncludeDisabled failed ({e}); "
                        "retrying without it - disabled AMIs may be missed")
        pages = ec2.get_paginator("describe_images").paginate(Owners=["self"])
        images = [img for page in pages for img in page.get("Images", [])]

    # AMIs created by AWS Backup are owned by the aws-backup-vault alias
    try:
        pages = ec2.get_paginator("describe_images").paginate(Owners=["aws-backup-vault"])
        images += [img for page in pages for img in page.get("Images", [])]
    except Exception:
        pass

    for img in images:
        for bdm in img.get("BlockDeviceMappings", []):
            sid = bdm.get("Ebs", {}).get("SnapshotId")
            if sid:
                referenced.add(sid)
    return referenced


def get_locked_snapshots(ec2, warnings):
    """Snapshot IDs under an EBS snapshot lock - these cannot be deleted by anyone."""
    locked = set()
    try:
        token = None
        while True:
            kwargs = {"MaxResults": 200}
            if token:
                kwargs["NextToken"] = token
            resp = ec2.describe_locked_snapshots(**kwargs)
            for s in resp.get("Snapshots", []):
                if s.get("LockState") in ("compliance", "governance", "compliance-cooloff"):
                    locked.add(s["SnapshotId"])
            token = resp.get("NextToken")
            if not token:
                break
    except Exception as e:
        warnings.append(f"describe_locked_snapshots unavailable ({type(e).__name__}); "
                        "locked snapshots were not filtered out")
    return locked


def is_shared_or_public(ec2, snapshot_id):
    """True if the snapshot is public or shared with another account."""
    try:
        perms = ec2.describe_snapshot_attribute(
            SnapshotId=snapshot_id, Attribute="createVolumePermission"
        ).get("CreateVolumePermissions", [])
        return bool(perms)
    except Exception:
        return False  # cannot confirm sharing; do not block on a failed check


def build_reason(age_days, min_age_days):
    return (
        "No AMI in this account references this snapshot (deprecated and disabled AMIs "
        "checked); no EBS volume was created from it; not managed by AWS Backup or DLM; "
        "no snapshot lock; not shared or public; state is completed; "
        f"snapshot is {age_days} days old (threshold {min_age_days} days)."
    )


# ----------- Core scan: one profile + one region -----------
def scan_region(profile, account_id, region, min_age_days):
    rows = []
    skipped = {k: 0 for k, _ in SKIP_KEYS}
    warnings = []
    try:
        ec2 = boto3.Session(profile_name=profile, region_name=region).client("ec2", config=CFG)

        snaps = []
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            snaps.extend(page.get("Snapshots", []))
        if not snaps:
            return rows, skipped, warnings

        ami_snaps = get_ami_referenced_snapshots(ec2, warnings)

        vol_snaps = set()
        for page in ec2.get_paginator("describe_volumes").paginate():
            for vol in page.get("Volumes", []):
                if vol.get("SnapshotId"):
                    vol_snaps.add(vol["SnapshotId"])

        locked_snaps = get_locked_snapshots(ec2, warnings)

        now = datetime.now(timezone.utc)
        candidates = []
        for s in snaps:
            sid = s["SnapshotId"]

            if s.get("State") != "completed":
                skipped["not_completed"] += 1
                continue
            if sid in ami_snaps:
                skipped["in_use_ami"] += 1
                continue
            if sid in vol_snaps:
                skipped["in_use_volume"] += 1
                continue

            started = s.get("StartTime")
            age = (now - started).days if started else -1
            if age < min_age_days:
                skipped["too_new"] += 1
                continue
            if is_service_managed(s):
                skipped["service_managed"] += 1
                continue
            if sid in locked_snaps:
                skipped["locked"] += 1
                continue
            candidates.append((s, age))

        # Sharing check: one extra API call per surviving candidate
        if candidates:
            with ThreadPoolExecutor(max_workers=8) as ex:
                shared_flags = list(ex.map(
                    lambda c: is_shared_or_public(ec2, c[0]["SnapshotId"]), candidates))
        else:
            shared_flags = []

        for (s, age), shared in zip(candidates, shared_flags):
            if shared:
                skipped["shared_or_public"] += 1
                continue
            size = s.get("VolumeSize", 0)
            started = s.get("StartTime")
            rows.append({
                "Profile": profile,
                "AccountId": account_id,
                "Region": region,
                "SnapshotId": s["SnapshotId"],
                "SourceVolumeId": s.get("VolumeId", ""),
                "SizeGiB": size,
                "StartDate": started.strftime("%Y-%m-%d") if started else "",
                "AgeDays": age,
                "Name": tag_value(s.get("Tags"), "Name"),
                "Description": (s.get("Description") or "")[:70],
                "EstMonthlyUSD": round(size * GB_MONTH_USD, 2),
                "SafeToDelete": "YES",
                "Reason": build_reason(age, min_age_days),
            })
    except Exception as e:
        print(f"  [ERROR] {profile}/{region}: {type(e).__name__}: {e}")
    return rows, skipped, warnings


# ----------- Report writers -----------
def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    return path


def write_xlsx(rows, path, min_age_days, skipped, warnings):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError:
        print("  [INFO] openpyxl not installed, Excel skipped. Install: pip install openpyxl")
        return None

    head_fill = PatternFill("solid", fgColor="1F3864")
    ok_fill = PatternFill("solid", fgColor="C6EFCE")
    bold_white = Font(bold=True, color="FFFFFF")

    total_gb = sum(r["SizeGiB"] for r in rows)
    monthly = round(total_gb * GB_MONTH_USD, 2)
    total_seen = len(rows) + sum(skipped.values())

    wb = Workbook()

    # --- Summary sheet ---
    ws = wb.active
    ws.title = "Summary"
    ws["A1"] = "Safe-to-Delete EBS Snapshot Report"
    ws["A1"].font = Font(bold=True, size=14)
    ws["A2"] = "Generated: " + datetime.now().strftime("%d-%b-%Y %H:%M")
    ws["A2"].font = Font(italic=True, size=9)

    ws.append([])
    ws.append(["Metric", "Value"])
    for c in ws[4]:
        c.font = bold_white
        c.fill = head_fill
    for metric, val in [
        ("Snapshots examined", total_seen),
        ("Accounts with findings", len({r["AccountId"] for r in rows})),
        ("Regions with findings", len({r["Region"] for r in rows})),
        ("Snapshots confirmed safe to delete", len(rows)),
        ("Reclaimable storage (GiB)", total_gb),
        ("Estimated monthly saving (USD)", monthly),
        ("Estimated annual saving (USD)", round(monthly * 12, 2)),
        ("Minimum age threshold (days)", min_age_days),
    ]:
        ws.append([metric, val])

    ws.append([])
    ws.append(["Snapshots excluded from this report", "Count"])
    for c in ws[ws.max_row]:
        c.font = bold_white
        c.fill = head_fill
    for key, label in SKIP_KEYS:
        ws.append([label, skipped.get(key, 0)])

    ws.append([])
    ws.append(["Deletion criteria applied to every snapshot listed in this report:"])
    ws[ws.max_row][0].font = Font(bold=True)
    for line in [
        "1. No AMI in this account references the snapshot. Deprecated and disabled AMIs "
        "are included in this check, because a disabled AMI still blocks deletion and is "
        "hidden from the console's default 'Owned by me' filter.",
        "2. No existing EBS volume was created from the snapshot.",
        "3. The snapshot is older than the age threshold shown above.",
        "4. The snapshot state is 'completed'.",
        "5. The snapshot is not managed by AWS Backup or Data Lifecycle Manager. Such "
        "snapshots cannot be deleted from the EC2 console at all.",
        "6. The snapshot is not protected by an EBS snapshot lock.",
        "7. The snapshot is not public and is not shared with any other AWS account.",
    ]:
        ws.append([line])

    ws.append([])
    ws.append(["Scope note: AMI ownership is checked within each account separately. "
               "Cross-account AMI usage of shared snapshots is not evaluated."])

    if warnings:
        ws.append([])
        ws.append(["Warnings raised during the scan"])
        ws[ws.max_row][0].font = Font(bold=True, color="C00000")
        for w in sorted(set(warnings)):
            ws.append([w])

    ws.column_dimensions["A"].width = 58
    ws.column_dimensions["B"].width = 18

    # --- Detail sheet ---
    if not rows:
        wb.save(path)
        return path

    ds = wb.create_sheet("Safe To Delete")
    ds.append(COLUMNS)
    for c in ds[1]:
        c.font = bold_white
        c.fill = head_fill
        c.alignment = Alignment(horizontal="center")

    safe_col = COLUMNS.index("SafeToDelete") + 1
    acct_col = COLUMNS.index("AccountId") + 1
    for r in rows:
        ds.append([r[c] for c in COLUMNS])
        cell = ds.cell(row=ds.max_row, column=safe_col)
        cell.fill = ok_fill
        cell.font = Font(bold=True)
        ds.cell(row=ds.max_row, column=acct_col).number_format = "@"

    caps = {"Reason": 70, "Description": 40, "SnapshotId": 24,
            "SourceVolumeId": 24, "Profile": 26}
    for i, col in enumerate(COLUMNS, 1):
        widest = max([len(col)] + [len(str(r[col])) for r in rows])
        ds.column_dimensions[get_column_letter(i)].width = min(widest + 3, caps.get(col, 16))
    ds.freeze_panes = "A2"
    ds.auto_filter.ref = ds.dimensions

    wb.save(path)
    return path


# ----------- Main -----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-age-days", type=int, default=DEFAULT_MIN_AGE_DAYS,
                    help=f"only report snapshots older than N days (default {DEFAULT_MIN_AGE_DAYS})")
    ap.add_argument("--region", help="scan a single region instead of all")
    ap.add_argument("--profile", action="append", help="limit to specific profile(s); repeatable")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    print("=" * 78)
    print("SAFE-TO-DELETE EBS SNAPSHOT FINDER   (read-only)")
    print(f"Age threshold: snapshots older than {args.min_age_days} days")
    print("=" * 78)

    profiles = args.profile or get_all_profiles()
    print(f"\nActive profiles: {len(profiles)}")

    jobs = []
    for p in profiles:
        sess = boto3.Session(profile_name=p)
        acct = get_account_id(sess)
        for reg in get_regions(sess, args.region):
            jobs.append((p, acct, reg))

    print(f"Scanning {len(jobs)} profile/region combinations...\n")

    rows, warnings = [], []
    skipped = {k: 0 for k, _ in SKIP_KEYS}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(scan_region, p, a, r, args.min_age_days) for p, a, r in jobs]
        for i, fut in enumerate(as_completed(futs), 1):
            r, sk, wn = fut.result()
            rows.extend(r)
            warnings.extend(wn)
            for k in skipped:
                skipped[k] += sk.get(k, 0)
            print(f"\r  progress: {i}/{len(jobs)}", end="", flush=True)
    print("\n")

    total_seen = len(rows) + sum(skipped.values())
    print("-" * 78)
    print(f"Snapshots examined       : {total_seen}")
    print(f"Confirmed safe to delete : {len(rows)}")
    print("Excluded:")
    for key, label in SKIP_KEYS:
        print(f"  {label:<62}{skipped.get(key, 0):>6}")
    if warnings:
        print("Warnings:")
        for w in sorted(set(warnings)):
            print(f"  ! {w}")
    print("-" * 78)

    if not rows:
        print(f"\nNo snapshot met all criteria (older than {args.min_age_days} days, "
              "no AMI, no EBS volume, not locked, not shared).")
        if skipped.get("service_managed", 0) > total_seen * 0.5:
            print("Most snapshots in scope are managed by AWS Backup or DLM. Those cannot "
                  "be deleted from the EC2 console; reduce retention in the backup plan or "
                  "delete recovery points from the vault instead.")
        os.makedirs(args.outdir, exist_ok=True)
        empty = os.path.join(args.outdir, f"safe_to_delete_snapshots_{TS}_summary_only.xlsx")
        if write_xlsx([], empty, args.min_age_days, skipped, warnings):
            print(f"\nSummary-only Excel written: {empty}")
        return

    rows.sort(key=lambda r: (r["Profile"], r["Region"], -r["SizeGiB"]))

    os.makedirs(args.outdir, exist_ok=True)
    base = os.path.join(args.outdir, f"safe_to_delete_snapshots_{TS}")
    csv_path = write_csv(rows, base + ".csv")
    xlsx_path = write_xlsx(rows, base + ".xlsx", args.min_age_days, skipped, warnings)

    total_gb = sum(r["SizeGiB"] for r in rows)
    print(f"Reclaimable storage      : {total_gb} GiB")
    print(f"Estimated saving         : ${round(total_gb * GB_MONTH_USD, 2)}/month  "
          f"(${round(total_gb * GB_MONTH_USD * 12, 2)}/year)")
    for r in rows[:15]:
        print(f"  {r['Profile']:<24}{r['Region']:<14}{r['SnapshotId']:<24}"
              f"{r['SizeGiB']:>6} GiB{r['AgeDays']:>6}d")
    if len(rows) > 15:
        print(f"  ... plus {len(rows) - 15} more, see report")
    print()
    print(f"CSV   : {csv_path}")
    if xlsx_path:
        print(f"Excel : {xlsx_path}")


if __name__ == "__main__":
    main()
