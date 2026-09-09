"""
utils/notifier.py
Sends a scan-completion summary to a Slack or Discord webhook URL.
Both platforms accept a simple {"content": "..."} or {"text": "..."} JSON payload,
so this sends both keys for compatibility.
"""

import json
import urllib.request
import urllib.error
from utils.logger import get_logger

log = get_logger("notifier")


def send_webhook_notification(webhook_url: str, targets: list, elapsed: float, reports: dict):
    summary_lines = [f"*ReconToReport scan complete* — {len(targets)} target(s) in {elapsed}s"]
    for target in targets:
        report_paths = reports.get(target, {})
        summary_lines.append(f"• `{target}` -> {', '.join(report_paths.values()) if report_paths else 'no report'}")

    message = "\n".join(summary_lines)
    payload = json.dumps({"content": message, "text": message}).encode("utf-8")

    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        urllib.request.urlopen(req, timeout=10)
        log.info("Webhook notification sent")
    except urllib.error.URLError as e:
        log.warning(f"Failed to send webhook notification: {e}")
