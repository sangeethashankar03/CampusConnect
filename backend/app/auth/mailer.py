from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os


def send_verification_email(to_email: str, code: str) -> None:
    message = Mail(
        from_email=os.environ.get("MAIL_USERNAME"),
        to_emails=to_email,
        subject="Your CampusConnect verification code",
        plain_text_content=(
            f"Your CampusConnect verification code is: {code}\n\n"
            f"This code expires in 10 minutes. If you didn't request this, "
            f"you can safely ignore this email."
        )
    )
    sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
    sg.send(message)