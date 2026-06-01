from pathlib import Path


def save_html(report, path="report.html"):
    s = report["summary"]
    rows = ""
    for item in report["items"]:
        maps = ", ".join(item.get("maps", []))
        extra = f"<br><small>{maps}</small>" if maps else ""
        rows += f"<tr><td>{item['status']}</td><td>{item['title']}</td><td>{item['msg']}{extra}</td></tr>"

    html = f"""<!DOCTYPE html>
<html>
<head><title>Cloud Audit</title>
<style>
  body {{ font-family: sans-serif; margin: 2rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  td, th {{ border: 1px solid #ddd; padding: 8px; }}
  .score {{ font-size: 2rem; }}
</style>
</head>
<body>
  <h1>Cloud Audit Report</h1>
  <p>Account: {s['account']} | Score: <span class="score">{s['score']}%</span></p>
  <p>PASS: {s['pass']} | WARN: {s['warn']} | FAIL: {s['fail']}</p>
  <table>
    <tr><th>Status</th><th>Check</th><th>Details</th></tr>
    {rows}
  </table>
</body>
</html>"""
    Path(path).write_text(html)
