# Cloud Audit

Small AWS compliance checker. Scans IAM, S3, CloudTrail, Config, and security groups. Maps results to CIS, ISO 27001, and SOC 2.

## Setup

```bash
pip install -r requirements.txt
```

Needs AWS credentials (`aws configure` or env vars).

## Run

```bash
python main.py scan
python main.py scan my-profile -r us-east-1 -o ./reports
```

## Output

Prints PASS / FAIL / WARN to the terminal and writes `report.json` and `report.html`.

## Layout

```text
├── main.py
├── checks/
├── reports/
├── mappings/
└── tests/
```

## Tests

```bash
pip install pytest moto
pytest tests/
```
