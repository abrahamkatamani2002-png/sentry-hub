"""Sends the sign-in verification code by email (Gmail SMTP by default)."""
import smtplib
import ssl
from email.message import EmailMessage
from html import escape

OUTBOX = []  # used by MAIL_BACKEND=memory (tests)


class MailError(Exception):
    pass


def send_email(cfg, to, subject, text, html=None):
    backend = cfg.get("MAIL_BACKEND", "smtp")
    if backend == "memory":
        OUTBOX.append({"to": to, "subject": subject, "text": text, "html": html})
        return
    if backend == "console":
        print(f"\n--- email to {to} ---\n{subject}\n{text}\n---------------------\n", flush=True)
        return

    user, password = cfg.get("SMTP_USER"), cfg.get("SMTP_PASSWORD")
    if not user or not password:
        raise MailError("SMTP_USER / SMTP_PASSWORD are not set")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{cfg['APP_NAME']} <{cfg.get('MAIL_FROM') or user}>"
    msg["To"] = to
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")

    host, port = cfg["SMTP_HOST"], int(cfg["SMTP_PORT"])
    context = ssl.create_default_context()
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as smtp:
                smtp.login(user, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.starttls(context=context)
                smtp.login(user, password)
                smtp.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        raise MailError(f"{type(exc).__name__}: {exc}") from exc


def send_login_code(cfg, user, code, ttl_minutes=10):
    first = (user["full_name"].split() or ["there"])[0]
    subject = f"{code} is your Sentry Hub verification code"
    text = (
        f"Hi {first},\n\n"
        f"Your Sentry Hub verification code is: {code}\n\n"
        f"It expires in {ttl_minutes} minutes and can only be used once.\n"
        "If you didn't just try to sign in, someone may know your password. "
        "Please sign in and change it.\n\n"
        "— Sentry Hub"
    )
    html = f"""<!doctype html>
<html><body style="margin:0;background:#f3f5fb;font-family:Segoe UI,Arial,sans-serif;color:#26304f">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden">
<tr><td style="background:#4f46e5;background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:22px 28px;color:#ffffff;font-size:18px;font-weight:700">Sentry Hub</td></tr>
<tr><td style="padding:28px">
<p style="margin:0 0 12px;font-size:16px">Hi {escape(first)},</p>
<p style="margin:0 0 20px;font-size:15px;line-height:1.5">Use this code to finish signing in:</p>
<p style="margin:0 0 20px;text-align:center"><span style="display:inline-block;font-size:34px;letter-spacing:10px;font-weight:700;color:#0f1630;background:#f3f5fb;border-radius:12px;padding:14px 22px">{code}</span></p>
<p style="margin:0 0 8px;font-size:13px;color:#667091">It expires in {ttl_minutes} minutes and can only be used once.</p>
<p style="margin:0;font-size:13px;color:#667091">Didn't try to sign in? Someone may know your password &mdash; sign in and change it.</p>
</td></tr></table></td></tr></table></body></html>"""
    send_email(cfg, user["email"], subject, text, html)
