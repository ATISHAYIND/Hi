#!/usr/bin/env python3
"""
Old AMI + Snapshot Cleanup Report  (READ-ONLY)
----------------------------------------------
Most EBS snapshots in a daily-backup environment are held by an AMI, so they
cannot be deleted at snapshot level. The deletable unit is the AMI. This report
finds AMIs that are safe to remove, and lists the snapshots that each one frees.

Safety rules applied to every AMI listed:
  1. The AMI is older than the age threshold (default 90 days)
  2. Its source resource still has newer AMIs - the most recent ones are kept
     (default: 2 newest per resource, set with --keep)
  3. The AMI is not used by any instance, launch template, or launch configuration
  4. Every snapshot it holds is also older than the age threshold
  5. Snapshots shared by an AMI that is being kept are never listed

An AMI whose source resource cannot be determined is never listed, because its
retention group cannot be verified.

This script performs describe_* calls only. Nothing is ever deleted or
deregistered.

Usage:
    python3 old_ami_cleanup_report.py
    python3 old_ami_cleanup_report.py --min-age-days 180 --keep 3
"""

import argparse
import csv
import os
import re
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import boto3
from botocore.config import Config

CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"})
TS = datetime.now().strftime("%Y%m%d_%H%M%S")
GB_MONTH_USD = 0.05
DEFAULT_MIN_AGE_DAYS = 90
DEFAULT_KEEP = 2

CREATE_IMAGE_RE = re.compile(r"CreateImage\((i-[0-9a-f]+)\)")

AMI_COLUMNS = [
    "Profile", "AccountId", "Region", "AmiId", "AmiName", "AmiCreated", "AmiAgeDays",
    "AmiOwner", "SourceResource", "AmisInGroup", "NewerAmisKept", "NewestKeptAmi",
    "NewestKeptDate", "InUse", "SnapshotCount", "SnapshotGiB", "EstMonthlyUSD", "Action",
]

SNAP_COLUMNS = [
    "Profile", "AccountId", "Region", "SnapshotId", "HeldByAmi", "SourceResource",
    "SizeGiB", "StartDate", "AgeDays", "EstMonthlyUSD", "Action",
]

SKIP_KEYS = [
    ("too_new", "AMI younger than the age threshold"),
    ("kept_recent", "Kept as one of the newest AMIs for its source resource"),
    ("in_use", "In use by an instance, launch template, or launch configuration"),
    ("no_group", "Source resource could not be determined - not evaluated"),
    ("only_copy", "Only AMI for its source resource - never removed"),
    ("young_snapshot", "Holds at least one snapshot younger than the threshold"),
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


# ----------- Grouping: which server does this AMI belong to? -----------
def source_resource(img):
    """
    Identify the resource an AMI was created from, so AMIs of the same server
    can be grouped and the newest ones kept. Returns None when unknown.
    """
    tags = img.get("Tags") or []

    # AWS Backup tags the source instance/volume ARN on the AMI
    for key in ("aws:backup:source-resource", "aws:backup:source-resource-arn"):
        val = tag_value(tags, key)
        if val:
            return val.split("/")[-1]

    # CreateImage writes the source instance id into the description
    m = CREATE_IMAGE_RE.search(img.get("Description") or "")
    if m:
        return m.group(1)

    # Golden AMI pipelines usually keep a stable Name tag with a date suffix
    name_tag = tag_value(tags, "Name")
    if name_tag:
        return re.sub(r"[-_ ]?\d{4}[-_]?\d{2}[-_]?\d{2}.*$", "", name_tag).strip("-_ ") or name_tag

    # AWS Backup AMI names look like AwsBackup_i-0abc123_...
    name = img.get("Name") or ""
    m = re.search(r"(i-[0-9a-f]+)", name)
    if m:
        return m.group(1)

    return None


def get_images(ec2, warnings, profile, region):
    """All AMIs visible to this account, tagged with their owner class."""
    images = []
    try:
        pages = ec2.get_paginator("describe_images").paginate(
            Owners=["self"], IncludeDisabled=True, IncludeDeprecated=True)
        for page in pages:
            for img in page.get("Images", []):
                img["_owner_class"] = "self"
                images.append(img)
    except Exception as e:
        warnings.append(f"{profile}/{region}: describe_images with IncludeDisabled failed "
                        f"({type(e).__name__}); disabled AMIs may be missed")
        pages = ec2.get_paginator("describe_images").paginate(Owners=["self"])
        for page in pages:
            for img in page.get("Images", []):
                img["_owner_class"] = "self"
                images.append(img)

    try:
        pages = ec2.get_paginator("describe_images").paginate(Owners=["aws-backup-vault"])
        for page in pages:
            for img in page.get("Images", []):
                img["_owner_class"] = "aws-backup-vault"
                images.append(img)
    except Exception:
        pass
    return images


def get_amis_in_use(ec2, warnings, profile, region):
    """AMI IDs referenced by instances, launch templates, or launch configurations."""
    in_use = set()
    try:
        for page in ec2.get_paginator("describe_instances").paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    if inst.get("State", {}).get("Name") != "terminated" and inst.get("ImageId"):
                        in_use.add(inst["ImageId"])
    except Exception as e:
        warnings.append(f"{profile}/{region}: describe_instances failed ({type(e).__name__}); "
                        "in-use AMIs may be missed")

    try:
        for page in ec2.get_paginator("describe_launch_templates").paginate():
            for lt in page.get("LaunchTemplates", []):
                try:
                    vers = ec2.describe_launch_template_versions(
                        LaunchTemplateId=lt["LaunchTemplateId"],
                        Versions=["$Latest", "$Default"])
                    for v in vers.get("LaunchTemplateVersions", []):
                        img = (v.get("LaunchTemplateData") or {}).get("ImageId")
                        if img:
                            in_use.add(img)
                except Exception:
                    continue
    except Exception:
        pass

    try:
        asg = boto3.Session(profile_name=profile, region_name=region).client(
            "autoscaling", config=CFG)
        for page in asg.get_paginator("describe_launch_configurations").paginate():
            for lc in page.get("LaunchConfigurations", []):
                if lc.get("ImageId"):
                    in_use.add(lc["ImageId"])
    except Exception:
        pass

    return in_use


# ----------- Core scan: one profile + one region -----------
def scan_region(profile, account_id, region, min_age_days, keep):
    ami_rows, snap_rows, warnings = [], [], []
    skipped = {k: 0 for k, _ in SKIP_KEYS}
    try:
        ec2 = boto3.Session(profile_name=profile, region_name=region).client("ec2", config=CFG)

        images = get_images(ec2, warnings, profile, region)
        if not images:
            return ami_rows, snap_rows, skipped, warnings

        snap_info = {}
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            for s in page.get("Snapshots", []):
                snap_info[s["SnapshotId"]] = s

        in_use = get_amis_in_use(ec2, warnings, profile, region)
        now = datetime.now(timezone.utc)

        # Group AMIs by their source resource, newest first
        groups = defaultdict(list)
        for img in images:
            created = img.get("CreationDate")
            try:
                img["_created"] = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                    tzinfo=timezone.utc)
            except Exception:
                try:
                    img["_created"] = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(
                        tzinfo=timezone.utc)
                except Exception:
                    img["_created"] = None
            key = source_resource(img)
            if not key:
                skipped["no_group"] += 1
                continue
            groups[key].append(img)

        candidates = []  # (img, group_key, group_size, kept_list)
        for key, imgs in groups.items():
            imgs = [i for i in imgs if i["_created"]]
            if not imgs:
                continue
            imgs.sort(key=lambda i: i["_created"], reverse=True)

            if len(imgs) <= keep:
                # Nothing to remove: this resource has only its protected recent copies
                skipped["only_copy"] += len(imgs)
                continue

            kept, older = imgs[:keep], imgs[keep:]
            for img in older:
                age = (now - img["_created"]).days
                if age < min_age_days:
                    skipped["too_new"] += 1
                    continue
                if img["ImageId"] in in_use:
                    skipped["in_use"] += 1
                    continue
                candidates.append((img, key, len(imgs), kept))
            skipped["kept_recent"] += len(kept)

        # Snapshots held by AMIs that are NOT candidates must never be listed
        candidate_ids = {img["ImageId"] for img, _, _, _ in candidates}
        protected_snaps = set()
        for img in images:
            if img["ImageId"] in candidate_ids:
                continue
            for bdm in img.get("BlockDeviceMappings", []):
                sid = (bdm.get("Ebs") or {}).get("SnapshotId")
                if sid:
                    protected_snaps.add(sid)

        for img, key, group_size, kept in candidates:
            age = (now - img["_created"]).days
            sids = [(bdm.get("Ebs") or {}).get("SnapshotId")
                    for bdm in img.get("BlockDeviceMappings", [])]
            sids = [s for s in sids if s]

            # Every snapshot this AMI holds must itself be old enough
            too_young = False
            usable = []
            for sid in sids:
                s = snap_info.get(sid)
                if not s:
                    continue  # snapshot not owned by this account
                s_age = (now - s["StartTime"]).days
                if s_age < min_age_days:
                    too_young = True
                    break
                usable.append((sid, s, s_age))
            if too_young:
                skipped["young_snapshot"] += 1
                continue

            free_now = [(sid, s, a) for sid, s, a in usable if sid not in protected_snaps]
            total_gb = sum(s.get("VolumeSize", 0) for _, s, _ in free_now)
            backup_owned = img["_owner_class"] == "aws-backup-vault"

            action = ("Delete the recovery point in the AWS Backup vault - this removes the "
                      "AMI and its snapshots together"
                      if backup_owned else
                      "Deregister the AMI, then delete the snapshots listed for it")

            ami_rows.append({
                "Profile": profile,
                "AccountId": account_id,
                "Region": region,
                "AmiId": img["ImageId"],
                "AmiName": (img.get("Name") or "")[:60],
                "AmiCreated": img["_created"].strftime("%Y-%m-%d"),
                "AmiAgeDays": age,
                "AmiOwner": img["_owner_class"],
                "SourceResource": key,
                "AmisInGroup": group_size,
                "NewerAmisKept": len(kept),
                "NewestKeptAmi": kept[0]["ImageId"] if kept else "",
                "NewestKeptDate": kept[0]["_created"].strftime("%Y-%m-%d") if kept else "",
                "InUse": "No",
                "SnapshotCount": len(free_now),
                "SnapshotGiB": total_gb,
                "EstMonthlyUSD": round(total_gb * GB_MONTH_USD, 2),
                "Action": action,
            })

            for sid, s, s_age in free_now:
                size = s.get("VolumeSize", 0)
                snap_rows.append({
                    "Profile": profile,
                    "AccountId": account_id,
                    "Region": region,
                    "SnapshotId": sid,
                    "HeldByAmi": img["ImageId"],
                    "SourceResource": key,
                    "SizeGiB": size,
                    "StartDate": s["StartTime"].strftime("%Y-%m-%d"),
                    "AgeDays": s_age,
                    "EstMonthlyUSD": round(size * GB_MONTH_USD, 2),
                    "Action": ("Freed when the AWS Backup recovery point is deleted"
                               if backup_owned else
                               "Delete after the AMI above is deregistered"),
                })

    except Exception as e:
        print(f"  [ERROR] {profile}/{region}: {type(e).__name__}: {e}")
    return ami_rows, snap_rows, skipped, warnings


# ----------- Report writers -----------
def write_csv(rows, columns, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)
    return path


def write_xlsx(path, ami_rows, snap_rows, min_age_days, keep, skipped, warnings):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError:
        print("  [INFO] openpyxl not installed, Excel skipped. Install: pip install openpyxl")
        return None

    head_fill = PatternFill("solid", fgColor="1F3864")
    backup_fill = PatternFill("solid", fgColor="FFEB9C")
    bold_white = Font(bold=True, color="FFFFFF")

    total_gb = sum(r["SnapshotGiB"] for r in ami_rows)
    monthly = round(total_gb * GB_MONTH_USD, 2)
    self_amis = [r for r in ami_rows if r["AmiOwner"] == "self"]
    backup_amis = [r for r in ami_rows if r["AmiOwner"] == "aws-backup-vault"]

    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    ws["A1"] = "Old AMI and Snapshot Cleanup Report"
    ws["A1"].font = Font(bold=True, size=14)
    ws["A2"] = "Generated: " + datetime.now().strftime("%d-%b-%Y %H:%M")
    ws["A2"].font = Font(italic=True, size=9)

    ws.append([])
    ws.append(["Metric", "Value"])
    for c in ws[4]:
        c.font = bold_white
        c.fill = head_fill
    for metric, val in [
        ("Age threshold (days)", min_age_days),
        ("Newest AMIs kept per source resource", keep),
        ("", ""),
        ("AMIs safe to remove", len(ami_rows)),
        ("  of which self-owned (deregister directly)", len(self_amis)),
        ("  of which AWS Backup owned (delete recovery point)", len(backup_amis)),
        ("Source resources affected", len({r["SourceResource"] for r in ami_rows})),
        ("Accounts with findings", len({r["AccountId"] for r in ami_rows})),
        ("Regions with findings", len({r["Region"] for r in ami_rows})),
        ("", ""),
        ("Snapshots freed", len(snap_rows)),
        ("Reclaimable storage (GiB)", total_gb),
        ("Estimated monthly saving (USD)", monthly),
        ("Estimated annual saving (USD)", round(monthly * 12, 2)),
    ]:
        ws.append([metric, val])

    ws.append([])
    ws.append(["AMIs excluded from this report", "Count"])
    for c in ws[ws.max_row]:
        c.font = bold_white
        c.fill = head_fill
    for key, label in SKIP_KEYS:
        ws.append([label, skipped.get(key, 0)])

    ws.append([])
    ws.append(["Safety rules applied to every AMI listed"])
    ws[ws.max_row][0].font = Font(bold=True)
    for line in [
        f"1. The AMI is older than {min_age_days} days.",
        f"2. Its source resource still has newer AMIs. The {keep} most recent AMIs of every "
        "source resource are kept and never appear in this report, so no resource is left "
        "without a current image.",
        "3. A source resource that has only its recent AMIs contributes nothing to this report.",
        "4. The AMI is not referenced by any instance, launch template, or launch configuration.",
        f"5. Every snapshot held by the AMI is also older than {min_age_days} days. If even one "
        "is newer, the whole AMI is excluded.",
        "6. Snapshots that are also held by an AMI being kept are never listed for deletion.",
        "7. An AMI whose source resource could not be identified is never listed, because its "
        "retention group cannot be verified.",
    ]:
        ws.append([line])

    ws.append([])
    ws.append(["Order of operations"])
    ws[ws.max_row][0].font = Font(bold=True)
    for line in [
        "Self-owned AMIs: deregister the AMI first, then delete its snapshots. A snapshot "
        "cannot be deleted while any registered AMI still references it.",
        "AWS Backup owned AMIs: do not deregister them directly. Delete the corresponding "
        "recovery point in the backup vault, which removes the AMI and its snapshots together.",
        "Cost is estimated at $0.05/GiB-month against the snapshot's provisioned volume size. "
        "EBS snapshots are incremental, so actual billed storage is lower. Treat these figures "
        "as an upper bound for prioritisation, not as a billing reconciliation.",
    ]:
        ws.append([line])

    if warnings:
        ws.append([])
        ws.append(["Warnings raised during the scan"])
        ws[ws.max_row][0].font = Font(bold=True, color="C00000")
        for w in sorted(set(warnings))[:60]:
            ws.append([w])

    ws.column_dimensions["A"].width = 62
    ws.column_dimensions["B"].width = 16

    def add_sheet(title, rows, columns, caps, backup_col=None):
        if not rows:
            return
        sh = wb.create_sheet(title)
        sh.append(columns)
        for c in sh[1]:
            c.font = bold_white
            c.fill = head_fill
            c.alignment = Alignment(horizontal="center")
        acct_col = columns.index("AccountId") + 1
        for r in rows:
            sh.append([r[c] for c in columns])
            sh.cell(row=sh.max_row, column=acct_col).number_format = "@"
            if backup_col and r.get("AmiOwner") == "aws-backup-vault":
                sh.cell(row=sh.max_row, column=columns.index(backup_col) + 1).fill = backup_fill
        for i, col in enumerate(columns, 1):
            widest = max([len(col)] + [len(str(r[col])) for r in rows])
            sh.column_dimensions[get_column_letter(i)].width = min(widest + 3, caps.get(col, 16))
        sh.freeze_panes = "A2"
        sh.auto_filter.ref = sh.dimensions

    add_sheet("AMIs To Remove", ami_rows, AMI_COLUMNS,
              {"Action": 60, "AmiName": 40, "SourceResource": 26, "Profile": 26},
              backup_col="AmiOwner")
    add_sheet("Snapshots Freed", snap_rows, SNAP_COLUMNS,
              {"Action": 50, "SourceResource": 26, "Profile": 26})

    wb.save(path)
    return path


# ----------- Main -----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-age-days", type=int, default=DEFAULT_MIN_AGE_DAYS,
                    help=f"only consider AMIs and snapshots older than N days "
                         f"(default {DEFAULT_MIN_AGE_DAYS})")
    ap.add_argument("--keep", type=int, default=DEFAULT_KEEP,
                    help=f"newest AMIs to keep per source resource (default {DEFAULT_KEEP})")
    ap.add_argument("--region", help="scan a single region instead of all")
    ap.add_argument("--profile", action="append", help="limit to specific profile(s); repeatable")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    if args.keep < 1:
        print("--keep must be at least 1; every source resource must retain a current AMI.")
        sys.exit(1)

    print("=" * 78)
    print("OLD AMI AND SNAPSHOT CLEANUP REPORT   (read-only)")
    print(f"Age threshold: {args.min_age_days} days | Keeping newest {args.keep} AMIs per resource")
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

    ami_rows, snap_rows, warnings = [], [], []
    skipped = {k: 0 for k, _ in SKIP_KEYS}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(scan_region, p, a, r, args.min_age_days, args.keep)
                for p, a, r in jobs]
        for i, fut in enumerate(as_completed(futs), 1):
            ar, sr, sk, wn = fut.result()
            ami_rows.extend(ar)
            snap_rows.extend(sr)
            warnings.extend(wn)
            for k in skipped:
                skipped[k] += sk.get(k, 0)
            print(f"\r  progress: {i}/{len(jobs)}", end="", flush=True)
    print("\n")

    total_gb = sum(r["SnapshotGiB"] for r in ami_rows)
    print("-" * 78)
    print(f"AMIs safe to remove      : {len(ami_rows)}")
    print(f"  self-owned             : {sum(1 for r in ami_rows if r['AmiOwner'] == 'self')}")
    print(f"  AWS Backup owned       : "
          f"{sum(1 for r in ami_rows if r['AmiOwner'] == 'aws-backup-vault')}")
    print(f"Snapshots freed          : {len(snap_rows)}")
    print(f"Reclaimable storage      : {total_gb} GiB")
    print(f"Estimated saving         : ${round(total_gb * GB_MONTH_USD, 2)}/month  "
          f"(${round(total_gb * GB_MONTH_USD * 12, 2)}/year)")
    print("Excluded:")
    for key, label in SKIP_KEYS:
        print(f"  {label:<62}{skipped.get(key, 0):>6}")
    if warnings:
        print("Warnings:")
        for w in sorted(set(warnings))[:10]:
            print(f"  ! {w}")
    print("-" * 78)

    os.makedirs(args.outdir, exist_ok=True)
    base = os.path.join(args.outdir, f"old_ami_cleanup_{TS}")
    xlsx = write_xlsx(base + ".xlsx", ami_rows, snap_rows,
                      args.min_age_days, args.keep, skipped, warnings)

    if not ami_rows:
        print("\nNo AMI met all safety rules. See the excluded counts above.")
        if xlsx:
            print(f"Summary-only Excel written: {xlsx}")
        return

    for r in sorted(ami_rows, key=lambda x: -x["SnapshotGiB"])[:15]:
        print(f"  {r['Profile']:<24}{r['Region']:<14}{r['AmiId']:<23}"
              f"{r['AmiAgeDays']:>5}d{r['SnapshotGiB']:>7} GiB  {r['SourceResource'][:20]}")
    if len(ami_rows) > 15:
        print(f"  ... plus {len(ami_rows) - 15} more, see report")

    write_csv(ami_rows, AMI_COLUMNS, base + "_amis.csv")
    if snap_rows:
        write_csv(snap_rows, SNAP_COLUMNS, base + "_snapshots.csv")
    print()
    print(f"CSV   : {base}_amis.csv")
    if snap_rows:
        print(f"CSV   : {base}_snapshots.csv")
    if xlsx:
        print(f"Excel : {xlsx}")


if __name__ == "__main__":
    main()
