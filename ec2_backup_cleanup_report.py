#!/usr/bin/env python3
"""
EC2 Backup Cleanup Report  (READ-ONLY)
--------------------------------------
Scans AWS Backup vaults in us-west-2 and us-east-1 across every logged-in SSO
profile and splits EC2 and EBS recovery points older than 90 days into two
buckets:

  1. DELETE MANUALLY - no lifecycle configured, so nothing will ever remove
     them. These are the action items.
  2. AWS WILL DELETE - a retention period is set. Each row shows its own
     retention, its expiry date and the days remaining. No action needed.

For every row in bucket 1 the report also confirms:
  - whether the source instance still exists
  - whether that instance is still being backed up (recovery points in the
    last 30 days), so deleting an old copy never leaves a live server exposed

An EC2 recovery point IS an AMI: its ARN is arn:aws:ec2:<region>::image/ami-...
Deleting the recovery point in the vault deregisters that AMI and removes its
snapshots in one step. An EBS recovery point is the snapshot itself.
Never deregister these AMIs from the EC2 console - that orphans the vault record.

This script performs list_* and describe_* calls only. Nothing is deleted.

Usage:
    python3 ec2_backup_cleanup_report.py
    python3 ec2_backup_cleanup_report.py --min-age-days 180
"""

import argparse
import csv
import os
import re
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config

CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"})
TS = datetime.now().strftime("%Y%m%d_%H%M%S")
GB_MONTH_USD = 0.05
DEFAULT_MIN_AGE_DAYS = 90
REGIONS = ["us-west-2", "us-east-1"]
RESOURCE_TYPES = {"EC2", "EBS"}
ACTIVE_BACKUP_WINDOW_DAYS = 30

AMI_ARN_RE = re.compile(r"image/(ami-[0-9a-f]+)")
SNAP_ARN_RE = re.compile(r"snapshot/(snap-[0-9a-f]+)")
INSTANCE_RE = re.compile(r"(i-[0-9a-f]{8,})")
VOLUME_RE = re.compile(r"(vol-[0-9a-f]{8,})")

DELETE_COLUMNS = [
    "Profile", "AccountId", "Region", "VaultName", "ResourceType", "ResourceName",
    "SourceInstanceId", "AmiId", "SnapshotIds", "SnapshotCount", "SizeGiB",
    "CreatedOn", "AgeDays", "AgeYears", "RetentionSet", "SourceResourceExists",
    "ActiveBackupCoverage", "Verdict", "Reason", "EstMonthlyUSD", "RecoveryPointArn",
]

AUTO_COLUMNS = [
    "Profile", "AccountId", "Region", "VaultName", "ResourceType", "ResourceName",
    "AmiOrSnapshotId", "SizeGiB", "CreatedOn", "AgeDays", "RetentionDays",
    "ExpiresOn", "DaysToExpiry", "BackupPlan", "EstMonthlyUSD",
]

PLAN_COLUMNS = [
    "Profile", "AccountId", "Region", "PlanName", "RuleName", "TargetVault",
    "Schedule", "RetentionDays", "CopyToRegion", "CopyToVault", "CopyRetentionDays",
]


# ----------- Profiles -----------
def get_all_profiles():
    try:
        profiles = subprocess.check_output(
            ["aws", "configure", "list-profiles"], text=True
        ).splitlines()
        profiles = [p.strip() for p in profiles if p.strip()]
        if not profiles:
            raise Exception("No AWS profiles found. Please configure at least one profile.")
        valid = []
        for profile in profiles:
            try:
                boto3.Session(profile_name=profile).client("sts", config=CFG).get_caller_identity()
                valid.append(profile)
            except Exception:
                print(f"  [SKIP] Profile '{profile}' not logged in or token expired.")
        if not valid:
            raise Exception("No AWS SSO profiles are currently logged in. "
                            "Run 'aws sso login --profile <profile>'.")
        return valid
    except Exception as e:
        print(f"Error detecting AWS profiles: {e}")
        sys.exit(1)


def get_account_id(session):
    try:
        return session.client("sts", config=CFG).get_caller_identity()["Account"]
    except Exception:
        return "unknown"


def paginate(client, op, key, **kwargs):
    token = None
    while True:
        call = dict(kwargs)
        if token:
            call["NextToken"] = token
        resp = getattr(client, op)(**call)
        for item in resp.get(key, []):
            yield item
        token = resp.get("NextToken")
        if not token:
            return


def resource_name(rp):
    if rp.get("ResourceName"):
        return rp["ResourceName"]
    arn = rp.get("ResourceArn", "")
    return arn.split("/")[-1] if arn else ""


def source_id(rp):
    arn = rp.get("ResourceArn", "") or ""
    m = INSTANCE_RE.search(arn) or VOLUME_RE.search(arn)
    return m.group(1) if m else ""


# ----------- Scan one profile + region -----------
def scan_region(profile, account_id, region, min_age_days):
    delete_rows, auto_rows, plan_rows, warnings = [], [], [], []
    counts = defaultdict(int)
    try:
        sess = boto3.Session(profile_name=profile, region_name=region)
        backup = sess.client("backup", config=CFG)
        ec2 = sess.client("ec2", config=CFG)
        now = datetime.now(timezone.utc)
        recent_cutoff = now - timedelta(days=ACTIVE_BACKUP_WINDOW_DAYS)

        try:
            vaults = list(paginate(backup, "list_backup_vaults", "BackupVaultList"))
        except Exception as e:
            warnings.append(f"{profile}/{region}: cannot list backup vaults ({type(e).__name__})")
            return delete_rows, auto_rows, plan_rows, warnings, counts, set(), set()

        all_points = []
        for v in vaults:
            name = v["BackupVaultName"]
            try:
                all_points.extend(paginate(backup, "list_recovery_points_by_backup_vault",
                                           "RecoveryPoints", BackupVaultName=name))
            except Exception as e:
                warnings.append(f"{profile}/{region}/{name}: cannot list recovery points "
                                f"({type(e).__name__})")

        # Which source resources still receive backups? Checked across ALL types
        # and ages so a live server is never reported as unprotected.
        recently_backed_up = set()
        for rp in all_points:
            created = rp.get("CreationDate")
            if created and created >= recent_cutoff:
                sid = source_id(rp)
                if sid:
                    recently_backed_up.add(sid)

        no_lifecycle, with_lifecycle = [], []
        for rp in all_points:
            counts["total_points"] += 1
            if rp.get("ResourceType") not in RESOURCE_TYPES:
                counts["other_resource_type"] += 1
                continue
            created = rp.get("CreationDate")
            age = (now - created).days if created else -1
            if age < min_age_days:
                counts["too_new"] += 1
                continue
            delete_at = (rp.get("CalculatedLifecycle") or {}).get("DeleteAt")
            retention = (rp.get("Lifecycle") or {}).get("DeleteAfterDays")
            if delete_at or retention is not None:
                with_lifecycle.append((rp, age, retention, delete_at))
            else:
                no_lifecycle.append((rp, age))

        # ---- Bucket 2: AWS deletes these itself ----
        for rp, age, retention, delete_at in with_lifecycle:
            counts["auto_delete"] += 1
            size = round(rp.get("BackupSizeInBytes", 0) / (1024 ** 3), 2)
            arn = rp.get("RecoveryPointArn", "")
            m = AMI_ARN_RE.search(arn) or SNAP_ARN_RE.search(arn)
            auto_rows.append({
                "Profile": profile, "AccountId": account_id, "Region": region,
                "VaultName": rp.get("BackupVaultName", ""),
                "ResourceType": rp.get("ResourceType", ""),
                "ResourceName": resource_name(rp),
                "AmiOrSnapshotId": m.group(1) if m else "",
                "SizeGiB": size,
                "CreatedOn": rp["CreationDate"].strftime("%Y-%m-%d"),
                "AgeDays": age,
                "RetentionDays": retention if retention is not None else "Set by copy rule",
                "ExpiresOn": delete_at.strftime("%Y-%m-%d") if delete_at else "",
                "DaysToExpiry": (delete_at - now).days if delete_at else "",
                "BackupPlan": (rp.get("CreatedBy") or {}).get("BackupPlanName", ""),
                "EstMonthlyUSD": round(size * GB_MONTH_USD, 2),
            })

        # ---- Bucket 1: nothing will ever delete these ----
        ami_ids = []
        for rp, age in no_lifecycle:
            m = AMI_ARN_RE.search(rp.get("RecoveryPointArn", ""))
            if m:
                ami_ids.append(m.group(1))

        ami_snaps, snap_size = {}, {}
        if ami_ids:
            for i in range(0, len(ami_ids), 100):
                try:
                    imgs = ec2.describe_images(ImageIds=ami_ids[i:i + 100])["Images"]
                except Exception as e:
                    warnings.append(f"{profile}/{region}: describe_images failed "
                                    f"({type(e).__name__}); snapshot ids not resolved")
                    imgs = []
                for img in imgs:
                    sids = [(b.get("Ebs") or {}).get("SnapshotId")
                            for b in img.get("BlockDeviceMappings", [])]
                    ami_snaps[img["ImageId"]] = [s for s in sids if s]
            wanted = [s for v in ami_snaps.values() for s in v]
            for i in range(0, len(wanted), 200):
                try:
                    for s in ec2.describe_snapshots(SnapshotIds=wanted[i:i + 200])["Snapshots"]:
                        snap_size[s["SnapshotId"]] = s.get("VolumeSize", 0)
                except Exception:
                    pass

        live_instances = set()
        try:
            for page in ec2.get_paginator("describe_instances").paginate():
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        if inst.get("State", {}).get("Name") != "terminated":
                            live_instances.add(inst["InstanceId"])
            instances_ok = True
        except Exception as e:
            instances_ok = False
            warnings.append(f"{profile}/{region}: describe_instances failed "
                            f"({type(e).__name__}); existence not verified")

        for rp, age in no_lifecycle:
            counts["manual_delete"] += 1
            arn = rp.get("RecoveryPointArn", "")
            size = round(rp.get("BackupSizeInBytes", 0) / (1024 ** 3), 2)
            m_ami = AMI_ARN_RE.search(arn)
            m_snap = SNAP_ARN_RE.search(arn)
            ami = m_ami.group(1) if m_ami else ""
            sids = ami_snaps.get(ami, []) if ami else ([m_snap.group(1)] if m_snap else [])
            sid_src = source_id(rp)

            if not sid_src or not sid_src.startswith("i-"):
                exists = "Unknown"
            elif not instances_ok:
                exists = "Not verified"
            else:
                exists = "Yes" if sid_src in live_instances else "No - decommissioned"

            covered = "Yes" if sid_src in recently_backed_up else "No"

            if exists.startswith("No"):
                verdict = "SAFE TO DELETE"
                reason = (f"No retention configured, so nothing will ever remove it. "
                          f"Sitting for {age} days since {rp['CreationDate']:%Y-%m-%d}. "
                          f"Source instance {sid_src} no longer exists in this region.")
            elif exists == "Yes" and covered == "Yes":
                verdict = "SAFE TO DELETE"
                reason = (f"No retention configured, so nothing will ever remove it. "
                          f"Sitting for {age} days since {rp['CreationDate']:%Y-%m-%d}. "
                          f"Source instance {sid_src} is still backed up - recovery points "
                          f"exist within the last {ACTIVE_BACKUP_WINDOW_DAYS} days, so "
                          f"protection continues after this copy is removed.")
            elif exists == "Yes" and covered == "No":
                verdict = "HOLD"
                reason = (f"No retention configured and {age} days old, but source instance "
                          f"{sid_src} is still running and has NO recovery point in the last "
                          f"{ACTIVE_BACKUP_WINDOW_DAYS} days. Removing this copy could leave a "
                          "live server without any backup. Fix backup coverage first.")
            else:
                verdict = "HOLD"
                reason = (f"No retention configured and {age} days old, but the source resource "
                          "could not be identified or verified, so nothing confirms it is safe.")
                counts["hold_unverified"] += 1

            if verdict == "HOLD":
                counts["hold"] += 1
            else:
                counts["safe"] += 1

            delete_rows.append({
                "Profile": profile, "AccountId": account_id, "Region": region,
                "VaultName": rp.get("BackupVaultName", ""),
                "ResourceType": rp.get("ResourceType", ""),
                "ResourceName": resource_name(rp),
                "SourceInstanceId": sid_src,
                "AmiId": ami,
                "SnapshotIds": ", ".join(sids),
                "SnapshotCount": len(sids),
                "SizeGiB": size,
                "CreatedOn": rp["CreationDate"].strftime("%Y-%m-%d"),
                "AgeDays": age,
                "AgeYears": round(age / 365.0, 1),
                "RetentionSet": "None - no lifecycle configured",
                "SourceResourceExists": exists,
                "ActiveBackupCoverage": covered,
                "Verdict": verdict,
                "Reason": reason,
                "EstMonthlyUSD": round(size * GB_MONTH_USD, 2),
                "RecoveryPointArn": arn,
            })

        # ---- Backup plan rules (EC2 relevant) ----
        try:
            for plan in paginate(backup, "list_backup_plans", "BackupPlansList"):
                try:
                    detail = backup.get_backup_plan(BackupPlanId=plan["BackupPlanId"])
                except Exception:
                    continue
                pname = detail.get("BackupPlan", {}).get("BackupPlanName", "")
                for rule in detail.get("BackupPlan", {}).get("Rules", []):
                    lc = rule.get("Lifecycle") or {}
                    base = {
                        "Profile": profile, "AccountId": account_id, "Region": region,
                        "PlanName": pname, "RuleName": rule.get("RuleName", ""),
                        "TargetVault": rule.get("TargetBackupVaultName", ""),
                        "Schedule": rule.get("ScheduleExpression", ""),
                        "RetentionDays": lc.get("DeleteAfterDays", "Not set"),
                        "CopyToRegion": "", "CopyToVault": "", "CopyRetentionDays": "",
                    }
                    copies = rule.get("CopyActions") or []
                    if not copies:
                        plan_rows.append(base)
                        continue
                    for cp in copies:
                        carn = cp.get("DestinationBackupVaultArn", "")
                        parts = carn.split(":")
                        row = dict(base)
                        row["CopyToRegion"] = parts[3] if len(parts) > 3 else ""
                        row["CopyToVault"] = carn.split(":")[-1].split("/")[-1] if carn else ""
                        row["CopyRetentionDays"] = (cp.get("Lifecycle") or {}).get(
                            "DeleteAfterDays", "Not set")
                        plan_rows.append(row)
        except Exception as e:
            warnings.append(f"{profile}/{region}: cannot list backup plans ({type(e).__name__})")

    except Exception as e:
        print(f"  [ERROR] {profile}/{region}: {type(e).__name__}: {e}")
    return delete_rows, auto_rows, plan_rows, warnings, counts, set(), set()


# ----------- Excel -----------
def write_csv(rows, columns, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)
    return path


def write_xlsx(path, delete_rows, auto_rows, plan_rows, counts, warnings, min_age_days):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    head = PatternFill("solid", fgColor="1F3864")
    green = PatternFill("solid", fgColor="C6EFCE")
    red = PatternFill("solid", fgColor="FFC7CE")
    grey = PatternFill("solid", fgColor="D9D9D9")
    bw = Font(bold=True, color="FFFFFF")

    safe = [r for r in delete_rows if r["Verdict"] == "SAFE TO DELETE"]
    hold = [r for r in delete_rows if r["Verdict"] == "HOLD"]
    safe_gb = sum(r["SizeGiB"] for r in safe)
    auto_gb = sum(r["SizeGiB"] for r in auto_rows)
    gone = [r for r in safe if r["SourceResourceExists"].startswith("No")]
    alive = [r for r in safe if r["SourceResourceExists"] == "Yes"]

    wb = Workbook()

    # ---------- Summary ----------
    ws = wb.active
    ws.title = "Summary"
    ws["A1"] = "EC2 Backup Cleanup Report"
    ws["A1"].font = Font(bold=True, size=16)
    ws["A2"] = "Generated: " + datetime.now().strftime("%d-%b-%Y %H:%M") + \
               "   |   Regions: us-west-2, us-east-1   |   EC2 and EBS backups only"
    ws["A2"].font = Font(italic=True, size=9)

    ws.append([])
    ws.append(["WHAT THIS REPORT SAYS, IN SHORT"])
    ws[ws.max_row][0].font = Font(bold=True, size=12)
    for line in [
        f"AWS Backup is holding backup copies of our servers. Every copy normally has a "
        f"retention period, and AWS deletes it automatically when that period ends.",
        f"We found {len(delete_rows)} old copies that have NO retention period set. Nobody set "
        "a rule for them, so AWS will never delete them. They will sit and cost money forever.",
        f"Of those, {len(safe)} are safe to delete now and {len(hold)} need a check first.".replace(" 1 need a", " 1 needs a"),
        f"Deleting the safe ones frees {round(safe_gb):,} GiB and saves about "
        f"${round(safe_gb * GB_MONTH_USD):,} a month.",
        "Everything else that is old is fine. It has a retention period and AWS will remove it "
        "on its own. That list is in the 'AWS Will Delete' sheet with the exact dates.",
    ]:
        ws.append([line])

    ws.append([])
    ws.append(["THE NUMBERS", "Count", "GiB", "USD / month"])
    for c in ws[ws.max_row]:
        c.font = bw
        c.fill = head
    for label, rows_, cnt in [
        ("We delete manually - SAFE TO DELETE", safe, len(safe)),
        ("   of which the server no longer exists", gone, len(gone)),
        ("   of which the server is alive and still backed up", alive, len(alive)),
        ("We delete manually - HOLD, check first", hold, len(hold)),
        ("AWS deletes automatically - no action needed", auto_rows, len(auto_rows)),
    ]:
        gb = sum(r["SizeGiB"] for r in rows_)
        ws.append([label, cnt, round(gb), round(gb * GB_MONTH_USD)])
    ws.append(["Yearly saving from the safe list (USD)", "", "",
               round(safe_gb * GB_MONTH_USD * 12)])

    ws.append([])
    ws.append(["WHY DELETING THESE IS SAFE"])
    ws[ws.max_row][0].font = Font(bold=True, size=12)
    for line in [
        f"1. Every copy in the delete list is older than {min_age_days} days. Nothing recent is "
        "touched.",
        "2. Every copy in the delete list has NO retention period configured. No backup policy "
        "covers it, so deleting it does not break any policy.",
        "3. For each one we checked whether the source server still exists. Where the server is "
        "gone, there is nothing left to protect.",
        f"4. Where the server is still running, we checked that it has fresh backups from the "
        f"last {ACTIVE_BACKUP_WINDOW_DAYS} days. Protection continues after the old copy is "
        "removed.",
        "5. Anything that failed either check is marked HOLD and is NOT in the delete list.",
        "6. Deleting a recovery point does NOT stop future backups. Backups run from the backup "
        "plan, not from the stored copies.",
    ]:
        ws.append([line])

    ws.append([])
    ws.append(["WHAT WE ACTUALLY DO"])
    ws[ws.max_row][0].font = Font(bold=True, size=12)
    for line in [
        "One action only: delete the recovery point in the AWS Backup vault.",
        "An EC2 recovery point is an AMI. Deleting the recovery point deregisters that AMI and "
        "removes its snapshots together. No separate AMI or snapshot deletion is needed.",
        "Do NOT deregister these AMIs from the EC2 console. That leaves the vault record "
        "pointing at nothing.",
        "The AMI and snapshot ids are listed in the report only so the deletion can be verified "
        "afterwards.",
    ]:
        ws.append([line])

    ws.append([])
    ws.append(["RETENTION POLICY IN FORCE TODAY (EC2 plans)"])
    ws[ws.max_row][0].font = Font(bold=True, size=12)
    ws.append(["Rule type", "Retention"])
    for c in ws[ws.max_row]:
        c.font = bw
        c.fill = head
    ec2_plans = [p for p in plan_rows
                 if "ec2" in (p["PlanName"] or "").lower() or "ec2" in (p["TargetVault"] or "").lower()]
    by_rule = defaultdict(set)
    for p in ec2_plans:
        rn = (p["RuleName"] or "").lower()
        kind = ("Daily" if "dail" in rn else "Weekly" if "week" in rn else
                "Monthly" if "month" in rn else "Yearly" if "year" in rn else "Other")
        by_rule[kind].add(str(p["RetentionDays"]))
    for kind in ("Daily", "Weekly", "Monthly", "Yearly", "Other"):
        if kind in by_rule:
            ws.append([kind, ", ".join(sorted(by_rule[kind])) + " days"])
    ws.append(["Full rule list with cross-region copy retention is in the "
               "'Retention Policy' sheet."])

    ws.append([])
    ws.append(["HOW THE COST FIGURE WAS CALCULATED"])
    ws[ws.max_row][0].font = Font(bold=True, size=12)
    for line in [
        f"Size x ${GB_MONTH_USD} per GiB per month.",
        "Size comes from the BackupSizeInBytes field, which reports the full size of the "
        "protected volume, not the incremental storage actually consumed. EBS backups are "
        "incremental, so the real bill is lower than the figure shown.",
        "Treat the saving as an upper bound for prioritisation. Confirm the billed amount in "
        "Cost Explorer under usage type EBS:SnapshotUsage before committing to a number.",
    ]:
        ws.append([line])

    if warnings:
        ws.append([])
        ws.append([f"SCAN GAPS ({len(set(warnings))} - the report does not cover these)"])
        ws[ws.max_row][0].font = Font(bold=True, size=12, color="C00000")
        for w in sorted(set(warnings))[:80]:
            ws.append([w])

    ws.column_dimensions["A"].width = 104
    for col in "BCD":
        ws.column_dimensions[col].width = 15

    # ---------- Detail sheets ----------
    def add_sheet(title, rows, columns, caps, verdict_col=None):
        if not rows:
            return
        sh = wb.create_sheet(title)
        sh.append(columns)
        for c in sh[1]:
            c.font = bw
            c.fill = head
            c.alignment = Alignment(horizontal="center")
        for r in rows:
            sh.append([r[c] for c in columns])
            sh.cell(row=sh.max_row, column=columns.index("AccountId") + 1).number_format = "@"
            if verdict_col:
                cell = sh.cell(row=sh.max_row, column=columns.index(verdict_col) + 1)
                cell.fill = green if r[verdict_col] == "SAFE TO DELETE" else red
                cell.font = Font(bold=True)
        for i, col in enumerate(columns, 1):
            widest = max([len(col)] + [len(str(r[col])) for r in rows])
            sh.column_dimensions[get_column_letter(i)].width = min(widest + 3, caps.get(col, 16))
        sh.freeze_panes = "A2"
        sh.auto_filter.ref = sh.dimensions
        return sh

    add_sheet("Delete Manually", safe + hold, DELETE_COLUMNS,
              {"Reason": 90, "SnapshotIds": 40, "RecoveryPointArn": 45, "VaultName": 30,
               "ResourceName": 26, "Profile": 30, "RetentionSet": 28,
               "SourceResourceExists": 22, "ActiveBackupCoverage": 20, "Verdict": 18},
              verdict_col="Verdict")

    auto = wb.create_sheet("AWS Will Delete")
    auto.append(["These recovery points are old but a retention period is set on each one. "
                 "AWS removes them on the date shown. No action is required."])
    auto[1][0].font = Font(bold=True)
    auto[1][0].fill = grey
    auto.append([])
    if auto_rows:
        by_ret = defaultdict(lambda: [0, 0.0])
        for r in auto_rows:
            k = str(r["RetentionDays"])
            by_ret[k][0] += 1
            by_ret[k][1] += r["SizeGiB"]
        auto.append(["Retention set", "Recovery points", "GiB", "USD / month"])
        for c in auto[auto.max_row]:
            c.font = bw
            c.fill = head
        for k, (cnt, gb) in sorted(by_ret.items(), key=lambda x: -x[1][0]):
            label = f"{k} days" if k.isdigit() else k
            auto.append([label, cnt, round(gb), round(gb * GB_MONTH_USD)])
        auto.append([])
        start = auto.max_row + 1
        auto.append(AUTO_COLUMNS)
        for c in auto[auto.max_row]:
            c.font = bw
            c.fill = head
            c.alignment = Alignment(horizontal="center")
        for r in auto_rows:
            auto.append([r[c] for c in AUTO_COLUMNS])
            auto.cell(row=auto.max_row,
                      column=AUTO_COLUMNS.index("AccountId") + 1).number_format = "@"
        caps = {"VaultName": 30, "ResourceName": 26, "Profile": 30, "BackupPlan": 34,
                "AmiOrSnapshotId": 24}
        for i, col in enumerate(AUTO_COLUMNS, 1):
            widest = max([len(col)] + [len(str(r[col])) for r in auto_rows])
            auto.column_dimensions[get_column_letter(i)].width = min(widest + 3, caps.get(col, 15))
        auto.freeze_panes = f"A{start + 1}"
    auto.column_dimensions["A"].width = 34

    add_sheet("Retention Policy", plan_rows, PLAN_COLUMNS,
              {"PlanName": 42, "RuleName": 34, "TargetVault": 32, "CopyToVault": 32,
               "Schedule": 26, "Profile": 30})

    # ---------- Method ----------
    mt = wb.create_sheet("Method & Checks")
    mt.append(["Method and Checks"])
    mt[1][0].font = Font(bold=True, size=14)
    mt.append([])
    mt.append(["Step", "Detail"])
    for c in mt[mt.max_row]:
        c.font = bw
        c.fill = head
    for step, detail in [
        ("Scope", "AWS Backup vaults in us-west-2 and us-east-1, every logged-in SSO profile."),
        ("Resource types", "EC2 and EBS only. RDS, FSx, DynamoDB and EFS are excluded."),
        ("Age filter", f"Recovery points older than {min_age_days} days."),
        ("Bucket split", "No Lifecycle and no CalculatedLifecycle.DeleteAt means nothing will "
                         "ever delete it, so it goes to Delete Manually. Anything with a "
                         "retention goes to AWS Will Delete."),
        ("AMI and snapshot ids", "An EC2 recovery point ARN is arn:aws:ec2:<region>::image/"
                                 "ami-xxxx. describe_images on that AMI returns its snapshots. "
                                 "An EBS recovery point ARN is the snapshot itself."),
        ("Server exists check", "describe_instances in the same region. Terminated instances "
                                "count as gone."),
        ("Backup coverage check", f"The source resource must have at least one recovery point "
                                  f"created in the last {ACTIVE_BACKUP_WINDOW_DAYS} days, in any "
                                  "vault in that region and of any resource type."),
        ("Verdict rule", "SAFE TO DELETE when the server is gone, or when the server exists and "
                         "still has fresh backups. HOLD in every other case."),
        ("APIs used", "backup:ListBackupVaults, ListRecoveryPointsByBackupVault, "
                      "ListBackupPlans, GetBackupPlan; ec2:DescribeImages, DescribeSnapshots, "
                      "DescribeInstances. All read-only."),
        ("Cost basis", f"SizeGiB x ${GB_MONTH_USD}/GiB-month. BackupSizeInBytes is the full "
                       "protected size, not incremental storage, so the figure is an upper "
                       "bound."),
    ]:
        mt.append([step, detail])

    mt.append([])
    mt.append(["Recovery points examined", "Count"])
    for c in mt[mt.max_row]:
        c.font = bw
        c.fill = head
    for key, label in [
        ("total_points", "Total recovery points seen in scope"),
        ("other_resource_type", "Excluded - not EC2 or EBS"),
        ("too_new", f"Excluded - newer than {min_age_days} days"),
        ("auto_delete", "Have a retention period - AWS will delete them"),
        ("manual_delete", "No retention period - examined for manual deletion"),
        ("safe", "   verdict SAFE TO DELETE"),
        ("hold", "   verdict HOLD"),
    ]:
        mt.append([label, counts.get(key, 0)])
    mt.column_dimensions["A"].width = 46
    mt.column_dimensions["B"].width = 96

    wb.save(path)
    return path


# ----------- Main -----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-age-days", type=int, default=DEFAULT_MIN_AGE_DAYS)
    ap.add_argument("--region", action="append", help="override the default two regions")
    ap.add_argument("--profile", action="append")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    regions = args.region or REGIONS
    print("=" * 78)
    print("EC2 BACKUP CLEANUP REPORT   (read-only)")
    print(f"Regions: {', '.join(regions)} | EC2 + EBS only | older than {args.min_age_days} days")
    print("=" * 78)

    profiles = args.profile or get_all_profiles()
    print(f"\nActive profiles: {len(profiles)}")

    jobs = []
    for p in profiles:
        acct = get_account_id(boto3.Session(profile_name=p))
        for r in regions:
            jobs.append((p, acct, r))
    print(f"Scanning {len(jobs)} profile/region combinations...\n")

    delete_rows, auto_rows, plan_rows, warnings = [], [], [], []
    counts = defaultdict(int)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(scan_region, p, a, r, args.min_age_days) for p, a, r in jobs]
        for i, fut in enumerate(as_completed(futs), 1):
            dr, ar, pr, wn, cn, _, _ = fut.result()
            delete_rows.extend(dr)
            auto_rows.extend(ar)
            plan_rows.extend(pr)
            warnings.extend(wn)
            for k, v in cn.items():
                counts[k] += v
            print(f"\r  progress: {i}/{len(jobs)}", end="", flush=True)
    print("\n")

    delete_rows.sort(key=lambda r: (r["Verdict"] != "SAFE TO DELETE", -r["SizeGiB"]))
    auto_rows.sort(key=lambda r: (r["DaysToExpiry"] if isinstance(r["DaysToExpiry"], int) else 9999))

    safe = [r for r in delete_rows if r["Verdict"] == "SAFE TO DELETE"]
    hold = [r for r in delete_rows if r["Verdict"] == "HOLD"]
    safe_gb = sum(r["SizeGiB"] for r in safe)

    print("-" * 78)
    print(f"DELETE MANUALLY - safe    : {len(safe)} points | {round(safe_gb)} GiB | "
          f"${round(safe_gb * GB_MONTH_USD)}/month (${round(safe_gb * GB_MONTH_USD * 12)}/year)")
    print(f"DELETE MANUALLY - hold    : {len(hold)} points")
    print(f"AWS WILL DELETE ITSELF    : {len(auto_rows)} points | "
          f"{round(sum(r['SizeGiB'] for r in auto_rows))} GiB")
    print(f"Backup plan rules found   : {len(plan_rows)}")
    if warnings:
        print(f"Scan gaps                 : {len(set(warnings))} (listed in the report)")
    print("-" * 78)
    for r in safe[:12]:
        print(f"  {r['Region']:<12}{r['VaultName'][:26]:<28}{str(r['ResourceName'])[:22]:<24}"
              f"{r['AgeDays']:>6}d{r['SizeGiB']:>9} GiB  {r['SourceResourceExists']}")
    if len(safe) > 12:
        print(f"  ... plus {len(safe) - 12} more in the report")

    os.makedirs(args.outdir, exist_ok=True)
    base = os.path.join(args.outdir, f"ec2_backup_cleanup_{TS}")
    xlsx = write_xlsx(base + ".xlsx", delete_rows, auto_rows, plan_rows,
                      counts, warnings, args.min_age_days)
    if delete_rows:
        write_csv(delete_rows, DELETE_COLUMNS, base + "_delete_manually.csv")
    if auto_rows:
        write_csv(auto_rows, AUTO_COLUMNS, base + "_aws_will_delete.csv")
    print()
    print(f"Excel : {xlsx}")
    if delete_rows:
        print(f"CSV   : {base}_delete_manually.csv")


if __name__ == "__main__":
    main()
