#!/usr/bin/env python3
"""
Old AMI + Snapshot Cleanup Report  (READ-ONLY)
----------------------------------------------
In a daily-backup environment nearly every EBS snapshot is held by an AMI, so
snapshots cannot be deleted at snapshot level. The deletable unit is the AMI.

What this report lists:
  Every AMI older than the age threshold (default 90 days), provided the same
  source resource also has an AMI created INSIDE the threshold window. Anything
  created in the last 90 days is never touched.

Safety rules:
  1. The AMI is older than the age threshold
  2. Its source resource has at least one AMI newer than the threshold, so the
     resource is never left without a current image
  3. The AMI is not used by any instance, launch template, or launch configuration
  4. Every snapshot it holds is also older than the threshold
  5. Snapshots also held by an AMI that is being kept are never listed

AMIs that fail rule 2, or whose source resource cannot be identified, are NOT
dropped silently - they go to the 'Needs Review' sheet with the reason.

This script performs describe_* calls only. Nothing is deleted or deregistered.

Usage:
    python3 old_ami_cleanup_report.py
    python3 old_ami_cleanup_report.py --min-age-days 180 --region us-west-2
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

CREATE_IMAGE_RE = re.compile(r"CreateImage\((i-[0-9a-f]+)\)")
INSTANCE_RE = re.compile(r"(i-[0-9a-f]{8,})")
DATE_SUFFIX_RE = re.compile(
    r"[-_. ]*(\d{4}[-_.]?\d{2}[-_.]?\d{2}|\d{8}|\d{10,13})([-_.T ]?\d{2}[-_.:]?\d{2}([-_.:]?\d{2})?Z?)?$"
)

AMI_COLUMNS = [
    "Profile", "AccountId", "Region", "AmiId", "AmiName", "AmiCreated", "AmiAgeDays",
    "AmiOwner", "SourceResource", "GroupedBy", "AmisInGroup", "RecentAmiCount",
    "NewestAmiId", "NewestAmiDate", "InUse", "SnapshotCount", "SnapshotGiB",
    "EstMonthlyUSD", "Action",
]

REVIEW_COLUMNS = [
    "Profile", "AccountId", "Region", "AmiId", "AmiName", "AmiCreated", "AmiAgeDays",
    "AmiOwner", "SourceResource", "AmisInGroup", "SnapshotCount", "SnapshotGiB",
    "EstMonthlyUSD", "ReviewReason",
]

SNAP_COLUMNS = [
    "Profile", "AccountId", "Region", "SnapshotId", "HeldByAmi", "SourceResource",
    "SizeGiB", "StartDate", "AgeDays", "EstMonthlyUSD", "Action",
]

SKIP_KEYS = [
    ("too_new", "Created inside the threshold window - never touched"),
    ("in_use", "In use by an instance, launch template, or launch configuration"),
    ("young_snapshot", "Holds at least one snapshot newer than the threshold"),
    ("no_recent_ami", "Moved to Needs Review: no recent AMI for this source resource"),
    ("no_group", "Moved to Needs Review: source resource could not be identified"),
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


# ----------- Grouping: which resource does this AMI belong to? -----------
def source_resource(img):
    """
    Returns (group_key, how_it_was_derived) or (None, None).
    Order matters: the most reliable signal is tried first.
    """
    tags = img.get("Tags") or []

    for key in ("aws:backup:source-resource", "aws:backup:source-resource-arn"):
        val = tag_value(tags, key)
        if val:
            return val.split("/")[-1], "backup tag"

    desc = img.get("Description") or ""
    m = CREATE_IMAGE_RE.search(desc)
    if m:
        return m.group(1), "CreateImage description"

    name = img.get("Name") or ""
    m = INSTANCE_RE.search(name) or INSTANCE_RE.search(desc)
    if m:
        return m.group(1), "instance id in name"

    for key in ("SourceInstance", "Server", "Hostname", "InstanceId", "source-instance"):
        val = tag_value(tags, key)
        if val:
            return val, f"{key} tag"

    name_tag = tag_value(tags, "Name")
    base = DATE_SUFFIX_RE.sub("", name_tag).strip("-_. ")
    if base and base != name_tag:
        return base, "Name tag minus date"

    base = DATE_SUFFIX_RE.sub("", name).strip("-_. ")
    if base and base != name:
        return base, "AMI name minus date"

    if name_tag:
        return name_tag, "Name tag as-is"

    return None, None


def get_images(ec2, warnings, profile, region):
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
        for page in ec2.get_paginator("describe_images").paginate(Owners=["self"]):
            for img in page.get("Images", []):
                img["_owner_class"] = "self"
                images.append(img)

    try:
        for page in ec2.get_paginator("describe_images").paginate(Owners=["aws-backup-vault"]):
            for img in page.get("Images", []):
                img["_owner_class"] = "aws-backup-vault"
                images.append(img)
    except Exception:
        pass
    return images


def get_amis_in_use(ec2, warnings, profile, region):
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


def parse_created(value):
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


# ----------- Core scan -----------
def scan_region(profile, account_id, region, min_age_days):
    ami_rows, review_rows, snap_rows, warnings = [], [], [], []
    skipped = {k: 0 for k, _ in SKIP_KEYS}
    group_methods = defaultdict(int)
    try:
        ec2 = boto3.Session(profile_name=profile, region_name=region).client("ec2", config=CFG)

        images = get_images(ec2, warnings, profile, region)
        if not images:
            return ami_rows, review_rows, snap_rows, skipped, warnings, group_methods

        snap_info = {}
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            for s in page.get("Snapshots", []):
                snap_info[s["SnapshotId"]] = s

        in_use = get_amis_in_use(ec2, warnings, profile, region)
        now = datetime.now(timezone.utc)

        groups = defaultdict(list)
        ungrouped = []
        for img in images:
            img["_created"] = parse_created(img.get("CreationDate", ""))
            if not img["_created"]:
                continue
            img["_age"] = (now - img["_created"]).days
            key, how = source_resource(img)
            img["_group"] = key
            img["_how"] = how or ""
            if key:
                group_methods[how] += 1
                groups[key].append(img)
            else:
                ungrouped.append(img)

        def snapshots_of(img):
            out = []
            for bdm in img.get("BlockDeviceMappings", []):
                sid = (bdm.get("Ebs") or {}).get("SnapshotId")
                if sid and sid in snap_info:
                    out.append((sid, snap_info[sid]))
            return out

        def gib(img):
            return sum(s.get("VolumeSize", 0) for _, s in snapshots_of(img))

        candidates = []
        for key, imgs in groups.items():
            imgs.sort(key=lambda i: i["_created"], reverse=True)
            recent = [i for i in imgs if i["_age"] < min_age_days]
            old = [i for i in imgs if i["_age"] >= min_age_days]
            skipped["too_new"] += len(recent)

            if not recent:
                # No current image for this resource - never propose deletion
                for img in old:
                    skipped["no_recent_ami"] += 1
                    review_rows.append({
                        "Profile": profile, "AccountId": account_id, "Region": region,
                        "AmiId": img["ImageId"], "AmiName": (img.get("Name") or "")[:60],
                        "AmiCreated": img["_created"].strftime("%Y-%m-%d"),
                        "AmiAgeDays": img["_age"], "AmiOwner": img["_owner_class"],
                        "SourceResource": key, "AmisInGroup": len(imgs),
                        "SnapshotCount": len(snapshots_of(img)), "SnapshotGiB": gib(img),
                        "EstMonthlyUSD": round(gib(img) * GB_MONTH_USD, 2),
                        "ReviewReason": f"This resource has no AMI newer than {min_age_days} "
                                        "days. Deleting this one would leave it with no image.",
                    })
                continue

            for img in old:
                candidates.append((img, key, len(imgs), recent))

        for img in ungrouped:
            if img["_age"] < min_age_days:
                skipped["too_new"] += 1
                continue
            skipped["no_group"] += 1
            review_rows.append({
                "Profile": profile, "AccountId": account_id, "Region": region,
                "AmiId": img["ImageId"], "AmiName": (img.get("Name") or "")[:60],
                "AmiCreated": img["_created"].strftime("%Y-%m-%d"),
                "AmiAgeDays": img["_age"], "AmiOwner": img["_owner_class"],
                "SourceResource": "", "AmisInGroup": "",
                "SnapshotCount": len(snapshots_of(img)), "SnapshotGiB": gib(img),
                "EstMonthlyUSD": round(gib(img) * GB_MONTH_USD, 2),
                "ReviewReason": "Source resource could not be identified from tags, name, "
                                "or description, so its retention group cannot be verified.",
            })

        # Snapshots held by any AMI that is NOT a candidate must never be listed
        candidate_ids = set()
        for img, key, gsize, recent in candidates:
            if img["ImageId"] in in_use:
                continue
            candidate_ids.add(img["ImageId"])

        protected_snaps = set()
        for img in images:
            if img["ImageId"] in candidate_ids:
                continue
            for bdm in img.get("BlockDeviceMappings", []):
                sid = (bdm.get("Ebs") or {}).get("SnapshotId")
                if sid:
                    protected_snaps.add(sid)

        for img, key, gsize, recent in candidates:
            if img["ImageId"] in in_use:
                skipped["in_use"] += 1
                continue

            pairs = snapshots_of(img)
            if any((now - s["StartTime"]).days < min_age_days for _, s in pairs):
                skipped["young_snapshot"] += 1
                continue

            free_now = [(sid, s) for sid, s in pairs if sid not in protected_snaps]
            total_gb = sum(s.get("VolumeSize", 0) for _, s in free_now)
            backup_owned = img["_owner_class"] == "aws-backup-vault"
            action = ("Delete the recovery point in the AWS Backup vault - this removes the "
                      "AMI and its snapshots together"
                      if backup_owned else
                      "Deregister the AMI, then delete the snapshots listed for it")

            ami_rows.append({
                "Profile": profile, "AccountId": account_id, "Region": region,
                "AmiId": img["ImageId"], "AmiName": (img.get("Name") or "")[:60],
                "AmiCreated": img["_created"].strftime("%Y-%m-%d"),
                "AmiAgeDays": img["_age"], "AmiOwner": img["_owner_class"],
                "SourceResource": key, "GroupedBy": img["_how"], "AmisInGroup": gsize,
                "RecentAmiCount": len(recent),
                "NewestAmiId": recent[0]["ImageId"],
                "NewestAmiDate": recent[0]["_created"].strftime("%Y-%m-%d"),
                "InUse": "No", "SnapshotCount": len(free_now), "SnapshotGiB": total_gb,
                "EstMonthlyUSD": round(total_gb * GB_MONTH_USD, 2), "Action": action,
            })

            for sid, s in free_now:
                size = s.get("VolumeSize", 0)
                snap_rows.append({
                    "Profile": profile, "AccountId": account_id, "Region": region,
                    "SnapshotId": sid, "HeldByAmi": img["ImageId"], "SourceResource": key,
                    "SizeGiB": size, "StartDate": s["StartTime"].strftime("%Y-%m-%d"),
                    "AgeDays": (now - s["StartTime"]).days,
                    "EstMonthlyUSD": round(size * GB_MONTH_USD, 2),
                    "Action": ("Freed when the AWS Backup recovery point is deleted"
                               if backup_owned else
                               "Delete after the AMI above is deregistered"),
                })

    except Exception as e:
        print(f"  [ERROR] {profile}/{region}: {type(e).__name__}: {e}")
    return ami_rows, review_rows, snap_rows, skipped, warnings, group_methods


# ----------- Report writers -----------
def write_csv(rows, columns, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)
    return path


def write_xlsx(path, ami_rows, review_rows, snap_rows, min_age_days,
               skipped, warnings, group_methods):
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
        ("", ""),
        ("AMIs safe to remove", len(ami_rows)),
        ("  of which self-owned (deregister directly)",
         sum(1 for r in ami_rows if r["AmiOwner"] == "self")),
        ("  of which AWS Backup owned (delete recovery point)",
         sum(1 for r in ami_rows if r["AmiOwner"] == "aws-backup-vault")),
        ("Source resources affected", len({r["SourceResource"] for r in ami_rows})),
        ("Accounts with findings", len({r["AccountId"] for r in ami_rows})),
        ("Regions with findings", len({r["Region"] for r in ami_rows})),
        ("", ""),
        ("Snapshots freed", len(snap_rows)),
        ("Reclaimable storage (GiB)", total_gb),
        ("Estimated monthly saving (USD)", monthly),
        ("Estimated annual saving (USD)", round(monthly * 12, 2)),
        ("", ""),
        ("AMIs needing manual review", len(review_rows)),
        ("Storage held by those (GiB)", sum(r["SnapshotGiB"] for r in review_rows)),
    ]:
        ws.append([metric, val])

    ws.append([])
    ws.append(["AMIs excluded from the deletion list", "Count"])
    for c in ws[ws.max_row]:
        c.font = bold_white
        c.fill = head_fill
    for key, label in SKIP_KEYS:
        ws.append([label, skipped.get(key, 0)])

    if group_methods:
        ws.append([])
        ws.append(["How source resources were identified", "AMIs"])
        for c in ws[ws.max_row]:
            c.font = bold_white
            c.fill = head_fill
        for how, cnt in sorted(group_methods.items(), key=lambda x: -x[1]):
            ws.append([how, cnt])

    ws.append([])
    ws.append(["Safety rules applied to every AMI in the deletion list"])
    ws[ws.max_row][0].font = Font(bold=True)
    for line in [
        f"1. The AMI is older than {min_age_days} days. Nothing created inside that window "
        "appears in this report.",
        f"2. Its source resource has at least one AMI newer than {min_age_days} days, shown in "
        "the NewestAmiId and NewestAmiDate columns, so the resource is never left without a "
        "current image.",
        "3. The AMI is not referenced by any instance, launch template, or launch configuration.",
        f"4. Every snapshot the AMI holds is also older than {min_age_days} days.",
        "5. Snapshots also referenced by an AMI that is being kept are excluded.",
        "6. An AMI whose source resource has no recent image, or cannot be identified at all, "
        "is listed in the Needs Review sheet instead of the deletion list.",
    ]:
        ws.append([line])

    ws.append([])
    ws.append(["Order of operations"])
    ws[ws.max_row][0].font = Font(bold=True)
    for line in [
        "Self-owned AMIs: deregister the AMI first, then delete its snapshots. A snapshot "
        "cannot be deleted while a registered AMI still references it.",
        "AWS Backup owned AMIs: do not deregister directly. Delete the matching recovery point "
        "in the backup vault, which removes the AMI and its snapshots together.",
        f"Cost is estimated at ${GB_MONTH_USD}/GiB-month against provisioned volume size. EBS "
        "snapshots are incremental, so billed storage is lower. Use these figures to rank work, "
        "not as a billing reconciliation.",
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
              {"Action": 58, "AmiName": 40, "SourceResource": 26, "GroupedBy": 24, "Profile": 26},
              backup_col="AmiOwner")
    add_sheet("Snapshots Freed", snap_rows, SNAP_COLUMNS,
              {"Action": 48, "SourceResource": 26, "Profile": 26})
    add_sheet("Needs Review", review_rows, REVIEW_COLUMNS,
              {"ReviewReason": 70, "AmiName": 40, "SourceResource": 26, "Profile": 26})

    wb.save(path)
    return path


# ----------- Main -----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-age-days", type=int, default=DEFAULT_MIN_AGE_DAYS,
                    help=f"AMIs and snapshots older than N days (default {DEFAULT_MIN_AGE_DAYS})")
    ap.add_argument("--region", help="scan a single region instead of all")
    ap.add_argument("--profile", action="append", help="limit to specific profile(s); repeatable")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    print("=" * 78)
    print("OLD AMI AND SNAPSHOT CLEANUP REPORT   (read-only)")
    print(f"Listing AMIs and snapshots older than {args.min_age_days} days")
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

    ami_rows, review_rows, snap_rows, warnings = [], [], [], []
    skipped = {k: 0 for k, _ in SKIP_KEYS}
    group_methods = defaultdict(int)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(scan_region, p, a, r, args.min_age_days) for p, a, r in jobs]
        for i, fut in enumerate(as_completed(futs), 1):
            ar, rr, sr, sk, wn, gm = fut.result()
            ami_rows.extend(ar)
            review_rows.extend(rr)
            snap_rows.extend(sr)
            warnings.extend(wn)
            for k in skipped:
                skipped[k] += sk.get(k, 0)
            for k, v in gm.items():
                group_methods[k] += v
            print(f"\r  progress: {i}/{len(jobs)}", end="", flush=True)
    print("\n")

    total_gb = sum(r["SnapshotGiB"] for r in ami_rows)
    print("-" * 78)
    print(f"AMIs safe to remove      : {len(ami_rows)}")
    print(f"Snapshots freed          : {len(snap_rows)}")
    print(f"Reclaimable storage      : {total_gb} GiB")
    print(f"Estimated saving         : ${round(total_gb * GB_MONTH_USD, 2)}/month  "
          f"(${round(total_gb * GB_MONTH_USD * 12, 2)}/year)")
    print(f"Needs manual review      : {len(review_rows)}")
    print("Excluded:")
    for key, label in SKIP_KEYS:
        print(f"  {label:<62}{skipped.get(key, 0):>6}")
    if group_methods:
        print("Grouping method used:")
        for how, cnt in sorted(group_methods.items(), key=lambda x: -x[1]):
            print(f"  {how:<62}{cnt:>6}")
    if warnings:
        print("Warnings:")
        for w in sorted(set(warnings))[:10]:
            print(f"  ! {w}")
    print("-" * 78)

    os.makedirs(args.outdir, exist_ok=True)
    base = os.path.join(args.outdir, f"old_ami_cleanup_{TS}")
    xlsx = write_xlsx(base + ".xlsx", ami_rows, review_rows, snap_rows,
                      args.min_age_days, skipped, warnings, group_methods)

    if ami_rows:
        write_csv(ami_rows, AMI_COLUMNS, base + "_amis.csv")
        print(f"CSV   : {base}_amis.csv")
    if snap_rows:
        write_csv(snap_rows, SNAP_COLUMNS, base + "_snapshots.csv")
        print(f"CSV   : {base}_snapshots.csv")
    if review_rows:
        write_csv(review_rows, REVIEW_COLUMNS, base + "_needs_review.csv")
        print(f"CSV   : {base}_needs_review.csv")
    if xlsx:
        print(f"Excel : {xlsx}")


if __name__ == "__main__":
    main()
