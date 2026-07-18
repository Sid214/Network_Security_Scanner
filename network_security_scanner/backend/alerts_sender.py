"""
GuardNet Alerts Sender — Platform Alerts Module
===============================================
Handles SMTP configurations, test emails, and background email dispatch
for new devices, disappeared devices, rogue devices, and port changes.
"""

import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any

try:
    from . import database
except ImportError:
    import database

def send_smtp_email_sync(smtp_settings: Dict[str, Any], subject: str, body: str):
    """Synchronous sender for SMTP alerts. Runs in background threads."""
    enabled = smtp_settings.get("smtp_enabled") == "true"
    if not enabled:
        return

    host = smtp_settings.get("smtp_host", "").strip()
    port_str = smtp_settings.get("smtp_port", "587").strip()
    username = smtp_settings.get("smtp_user", "").strip()
    password = smtp_settings.get("smtp_pass", "").strip()
    security = smtp_settings.get("smtp_security", "tls").strip().lower() # none | ssl | tls
    from_addr = smtp_settings.get("smtp_from", "").strip()
    to_addr = smtp_settings.get("alert_email", "").strip()

    if not host or not to_addr or not from_addr:
        print("[Alerts Sender] Missing SMTP host, sender, or destination email.")
        return

    try:
        port = int(port_str)
    except ValueError:
        port = 587

    # Build MIME message
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        if security == 'ssl':
            server = smtplib.SMTP_SSL(host, port, timeout=12)
        else:
            server = smtplib.SMTP(host, port, timeout=12)
            if security == 'tls':
                server.starttls()

        if username and password:
            server.login(username, password)

        server.sendmail(from_addr, to_addr, msg.as_string())
        server.quit()
        print(f"[Alerts Sender] Email alert sent to {to_addr}: {subject}")
    except Exception as e:
        print(f"[Alerts Sender] Error sending email alert: {e}")

def trigger_alert_email(severity: str, subject: str, message_html: str):
    """
    Checks DB settings and fires an alert email in a background daemon thread
    if SMTP is enabled and the alert meets the minimum severity threshold.
    """
    try:
        settings = database.get_settings()
    except Exception as e:
        print(f"[Alerts Sender] Failed to read settings from DB: {e}")
        return

    enabled = settings.get("smtp_enabled") == "true"
    if not enabled:
        return

    # Check severity filter
    min_severity = settings.get("alert_min_severity", "low").lower() # low | medium | high
    severity_order = {"low": 1, "medium": 2, "high": 3}
    
    alert_level = severity_order.get(severity.lower(), 1)
    filter_level = severity_order.get(min_severity, 1)

    if alert_level < filter_level:
        print(f"[Alerts Sender] Alert '{subject}' suppressed by severity filter ({severity} < {min_severity}).")
        return

    # Render HTML template wrapper
    body = f"""
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0f172a; color: #f1f5f9; padding: 20px; }}
            .card {{ border: 1px solid #1e293b; border-radius: 12px; background-color: #1e293b; padding: 24px; max-width: 600px; margin: 0 auto; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
            .header {{ display: flex; align-items: center; border-bottom: 2px solid #06b6d4; padding-bottom: 12px; margin-bottom: 16px; }}
            .title {{ font-size: 20px; font-weight: bold; color: #06b6d4; }}
            .meta {{ font-size: 11px; color: #94a3b8; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.05em; }}
            .content {{ font-size: 14px; line-height: 1.6; color: #cbd5e1; }}
            .badge {{ display: inline-block; padding: 4px 10px; border-radius: 99px; font-size: 11px; font-weight: bold; margin-right: 8px; text-transform: uppercase; }}
            .badge-high {{ background-color: #ef4444; color: #ffffff; }}
            .badge-medium {{ background-color: #f59e0b; color: #ffffff; }}
            .badge-low {{ background-color: #10b981; color: #ffffff; }}
            .footer {{ font-size: 11px; color: #64748b; text-align: center; margin-top: 24px; border-top: 1px solid #334155; padding-top: 12px; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="header">
                <span class="title">GuardNet Security Alert</span>
            </div>
            <div class="meta">
                <span class="badge badge-{severity.lower()}">{severity} Severity</span>
                <span>System Notification</span>
            </div>
            <div class="content">
                {message_html}
            </div>
            <div class="footer">
                GuardNet Network Security Suite • Dynamic Monitoring Active
            </div>
        </div>
    </body>
    </html>
    """

    t = threading.Thread(
        target=send_smtp_email_sync,
        args=(settings, subject, body),
        daemon=True
    )
    t.start()

def test_smtp_configuration(settings: Dict[str, Any]) -> str:
    """Synchronously sends a test email to verify settings. Returns error message or 'success'."""
    host = settings.get("smtp_host", "").strip()
    port_str = settings.get("smtp_port", "587").strip()
    username = settings.get("smtp_user", "").strip()
    password = settings.get("smtp_pass", "").strip()
    security = settings.get("smtp_security", "tls").strip().lower()
    from_addr = settings.get("smtp_from", "").strip()
    to_addr = settings.get("alert_email", "").strip()

    if not host: return "Missing SMTP server host."
    if not from_addr: return "Missing sender address (From Email)."
    if not to_addr: return "Missing recipient address (Alert Email)."

    try:
        port = int(port_str)
    except ValueError:
        return "Invalid port number."

    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = "GuardNet SMTP Server Connection Test"
    
    html = f"""
    <html>
        <body style="font-family: sans-serif; background-color: #070b13; color: #f1f5f9; padding: 20px;">
            <div style="border: 1px solid #06b6d4; border-radius: 8px; padding: 20px; background-color: #0f172a; max-width: 500px; margin: auto;">
                <h2 style="color: #06b6d4; margin-top: 0;">GuardNet Mailer Configuration Success</h2>
                <p>Your SMTP mail configurations are working properly. GuardNet security threat alerts will now be routed directly to this inbox.</p>
                <hr style="border: none; border-top: 1px solid #1e293b; margin: 15px 0;">
                <p style="font-size: 11px; color: #94a3b8;">Connection Profile: host={host}, port={port}, security={security}</p>
            </div>
        </body>
    </html>
    """
    msg.attach(MIMEText(html, 'html'))

    try:
        if security == 'ssl':
            server = smtplib.SMTP_SSL(host, port, timeout=12)
        else:
            server = smtplib.SMTP(host, port, timeout=12)
            if security == 'tls':
                server.starttls()

        if username and password:
            server.login(username, password)

        server.sendmail(from_addr, to_addr, msg.as_string())
        server.quit()
        return "success"
    except Exception as e:
        return str(e)
