"""
Generates a self-contained HTML security scan report from prediction results.
No external CSS/JS dependencies — everything is inline.
"""

import os
from datetime import datetime


_RISK_COLOURS = {
    "High":   ("#fde8e8", "#c0392b", "High"),
    "Medium": ("#fef9e7", "#d68910", "Medium"),
    "Low":    ("#eafaf1", "#1e8449", "Low"),
}


def _badge(risk: str) -> str:
    bg, fg, label = _RISK_COLOURS.get(risk, ("#eee", "#333", risk))
    return (
        f'<span style="background:{bg};color:{fg};border:1px solid {fg};'
        f'padding:2px 10px;border-radius:12px;font-weight:bold;'
        f'font-size:0.85em;">{label}</span>'
    )


def _prob_bar(probabilities: dict | None) -> str:
    if not probabilities:
        return "—"
    parts = []
    colour = {"High": "#c0392b", "Medium": "#d68910", "Low": "#1e8449"}
    for label, prob in probabilities.items():
        pct = int(prob * 100)
        c   = colour.get(label, "#999")
        parts.append(
            f'<span style="color:{c};font-weight:bold">{label}</span>'
            f'&nbsp;{pct}%'
        )
    return "&nbsp;&nbsp;|&nbsp;&nbsp;".join(parts)


def generate_html_report(
    scan_results: list[dict],
    source_label: str,
    output_path: str,
) -> str:
    """
    Writes a self-contained HTML report and returns the file path.

    Parameters
    ----------
    scan_results : list of dicts, each with keys:
        file (optional), resource_type, resource_name,
        risk_level, probabilities, reason, features
    source_label : title shown at top of the report (file path or directory)
    output_path  : where to write the .html file
    """
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in scan_results:
        counts[r["risk_level"]] += 1

    # Summary cards
    total = len(scan_results)
    cards_html = "".join([
        _summary_card("Total Resources", str(total),    "#2c3e50", "#ecf0f1"),
        _summary_card("High Risk",       str(counts["High"]),   "#c0392b", "#fde8e8"),
        _summary_card("Medium Risk",     str(counts["Medium"]), "#d68910", "#fef9e7"),
        _summary_card("Low Risk",        str(counts["Low"]),    "#1e8449", "#eafaf1"),
    ])

    # Group rows by file (for --dir scans)
    groups: dict[str, list] = {}
    for r in scan_results:
        key = r.get("file", source_label)
        groups.setdefault(key, []).append(r)

    sections_html = ""
    for file_key, rows in groups.items():
        table_rows = ""
        for r in rows:
            bg, _, _ = _RISK_COLOURS.get(r["risk_level"], ("#fff", "#000", ""))
            triggered = [
                k for k, v in r.get("features", {}).items()
                if k != "count_sensitive_indicators" and v
            ]
            feat_html = (
                "<br>".join(f"&bull;&nbsp;{f}" for f in triggered)
                if triggered else '<span style="color:#aaa">none</span>'
            )
            table_rows += f"""
            <tr style="background:{bg}">
              <td style="padding:8px 12px;font-family:monospace;font-size:0.85em">
                {r['resource_type']}<br>
                <strong>{r['resource_name']}</strong>
              </td>
              <td style="padding:8px 12px;text-align:center">{_badge(r['risk_level'])}</td>
              <td style="padding:8px 12px;font-size:0.85em">{_prob_bar(r.get('probabilities'))}</td>
              <td style="padding:8px 12px;font-size:0.85em">{r.get('reason','')}</td>
              <td style="padding:8px 12px;font-size:0.82em;color:#555">{feat_html}</td>
            </tr>"""

        file_counts = {"High": 0, "Medium": 0, "Low": 0}
        for r in rows:
            file_counts[r["risk_level"]] += 1

        sections_html += f"""
        <div style="margin-bottom:32px">
          <h3 style="font-family:monospace;font-size:0.95em;color:#34495e;
                     border-left:4px solid #2980b9;padding-left:10px;margin-bottom:6px">
            {file_key}
            &nbsp;
            <span style="font-weight:normal;color:#c0392b">High:{file_counts['High']}</span>
            &nbsp;
            <span style="font-weight:normal;color:#d68910">Medium:{file_counts['Medium']}</span>
            &nbsp;
            <span style="font-weight:normal;color:#1e8449">Low:{file_counts['Low']}</span>
          </h3>
          <table style="width:100%;border-collapse:collapse;font-size:0.9em">
            <thead>
              <tr style="background:#2c3e50;color:#fff">
                <th style="padding:8px 12px;text-align:left">Resource</th>
                <th style="padding:8px 12px">Risk</th>
                <th style="padding:8px 12px">Confidence</th>
                <th style="padding:8px 12px;text-align:left">Reason</th>
                <th style="padding:8px 12px;text-align:left">Triggered Features</th>
              </tr>
            </thead>
            <tbody>{table_rows}</tbody>
          </table>
        </div>"""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Terraform Security Scan Report</title>
  <style>
    body  {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
             margin:0; background:#f4f6f9; color:#2c3e50 }}
    .wrap {{ max-width:1200px; margin:0 auto; padding:24px }}
    h1    {{ font-size:1.4em; margin-bottom:4px }}
    .sub  {{ color:#7f8c8d; font-size:0.85em; margin-bottom:24px }}
    .cards{{ display:flex; gap:16px; margin-bottom:28px; flex-wrap:wrap }}
    table {{ box-shadow:0 1px 4px rgba(0,0,0,.12); border-radius:6px; overflow:hidden }}
    tr:hover td {{ filter:brightness(0.97) }}
    td,th {{ border-bottom:1px solid #e0e0e0 }}
  </style>
</head>
<body>
<div class="wrap">
  <h1>Terraform Security Scan Report</h1>
  <div class="sub">Source: <code>{source_label}</code> &nbsp;|&nbsp; Generated: {timestamp}</div>
  <div class="cards">{cards_html}</div>
  {sections_html}
  <p style="color:#aaa;font-size:0.8em;margin-top:32px">
    Generated by Terraform Security Misconfiguration Detector
    &nbsp;|&nbsp; Pre-Deployment Detection Using Machine Learning
  </p>
</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

    return output_path


def _summary_card(title: str, value: str, fg: str, bg: str) -> str:
    return (
        f'<div style="background:{bg};border-left:5px solid {fg};'
        f'padding:14px 20px;border-radius:6px;min-width:140px;'
        f'box-shadow:0 1px 4px rgba(0,0,0,.1)">'
        f'<div style="font-size:1.8em;font-weight:bold;color:{fg}">{value}</div>'
        f'<div style="color:{fg};font-size:0.85em;margin-top:2px">{title}</div>'
        f"</div>"
    )
