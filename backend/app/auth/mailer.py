
import smtplib
from email.mime.text import MIMEText
from flask import current_app


def send_verification_email(to_email: str, code: str) -> None:
    username = current_app.config["MAIL_USERNAME"]
    password = current_app.config["MAIL_PASSWORD"]

    if not username or not password:
        raise RuntimeError(
            "MAIL_USERNAME / MAIL_PASSWORD are not set. Add them to backend/.env "
            "(see README) before registration can send real emails."
        )

    body = (
        f"Your CampusConnect verification code is: {code}\n\n"
        f"This code expires in 10 minutes. If you didn't request this, "
        f"you can safely ignore this email."
    )
    msg = MIMEText(body)
    msg["Subject"] = "Your CampusConnect verification code"
    msg["From"] = username
    msg["To"] = to_email

    with smtplib.SMTP(current_app.config["MAIL_SERVER"], current_app.config["MAIL_PORT"]) as server:
        server.starttls()
        server.login(username, password)
        server.sendmail(username, [to_email], msg.as_string())