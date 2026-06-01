import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
import yaml

from checks.cloudtrail import check_cloudtrail
from checks.config import check_config
from checks.iam import check_iam
from checks.s3 import check_s3
from checks.security_groups import check_sgs
from reports.html import save_html
from reports.json import save_json

ROOT = Path(__file__).resolve().parent
MAPS_DIR = ROOT / "mappings"


def load_maps():
    out = {}
    for file in MAPS_DIR.glob("*.yaml"):
        name = file.stem.upper()
        if name == "ISO27001":
            name = "ISO 27001"
        data = yaml.safe_load(file.read_text()) or {}
        for check_id, info in data.items():
            label = f"{name} {info['id']}"
            out.setdefault(check_id, []).append(label)
    return out


def add_maps(items):
    maps = load_maps()
    for item in items:
        item["maps"] = maps.get(item["id"], [])


def score(items):
    if not items:
        return 100
    pts = 0
    for i in items:
        if i["status"] == "PASS":
            pts += 1
        elif i["status"] == "WARN":
            pts += 0.5
    return round(pts / len(items) * 100, 1)


def scan(profile=None, region="us-east-1"):
    session = boto3.Session(profile_name=profile, region_name=region)
    account = session.client("sts").get_caller_identity()["Account"]

    items = []
    items += check_iam(session)
    items += check_cloudtrail(session)
    items += check_s3(session)
    items += check_sgs(session)
    items += check_config(session)
    add_maps(items)

    summary = {
        "account": account,
        "region": region,
        "score": score(items),
        "pass": sum(1 for i in items if i["status"] == "PASS"),
        "warn": sum(1 for i in items if i["status"] == "WARN"),
        "fail": sum(1 for i in items if i["status"] == "FAIL"),
    }
    return {"time": datetime.now(timezone.utc).isoformat(), "summary": summary, "items": items}


def print_report(report):
    s = report["summary"]
    print(f"\nAccount: {s['account']}")
    print(f"Overall Score: {s['score']}%\n")

    for status, sym in [("PASS", "✓"), ("FAIL", "✗"), ("WARN", "!")]:
        group = [i for i in report["items"] if i["status"] == status]
        if not group:
            continue
        print(f"{status}:")
        for i in group:
            print(f"  {sym} {i['title']}")
            if i.get("maps") and status != "PASS":
                print(f"    -> {', '.join(i['maps'])}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Simple AWS compliance scan")
    parser.add_argument("cmd", nargs="?", default="scan", choices=["scan"])
    parser.add_argument("profile", nargs="?", help="AWS profile name")
    parser.add_argument("-r", "--region", default="us-east-1")
    parser.add_argument("-o", "--output", default=".")
    args = parser.parse_args()

    try:
        report = scan(profile=args.profile, region=args.region)
    except Exception as e:
        print(f"Scan failed: {e}")
        sys.exit(1)

    print_report(report)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    save_json(report, out / "report.json")
    save_html(report, out / "report.html")
    print(f"Wrote {out / 'report.json'} and {out / 'report.html'}")

    if report["summary"]["fail"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
