import json
from pathlib import Path


def save_json(report, path="report.json"):
    Path(path).write_text(json.dumps(report, indent=2))
