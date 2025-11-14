import logging
import os
import smtplib
import ssl
from typing import Dict, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from starlette.concurrency import run_in_threadpool
from fastapi import BackgroundTasks

from authtuna.core.config import settings

logger = logging.getLogger(__name__)


class EmailManager:
    """
    Manages all email-related operations, including sending emails
    and handling configurable templates. Uses Python's built-in smtplib
    for direct SMTP connections.
    """

    def __init__(self):
        self.smtp_server = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_username = settings.SMTP_USERNAME
        self.smtp_password = settings.SMTP_PASSWORD.get_secret_value() if settings.SMTP_PASSWORD else None
        self.sender_email = settings.DEFAULT_SENDER_EMAIL
        self.use_credentials = settings.USE_CREDENTIALS
        self.template_dir = Path(settings.EMAIL_TEMPLATE_DIR)
        self.template_cache = {}

    def _get_template(self, template_name: str) -> str:
        """
        Retrieves a template from the cache, loading from disk if necessary.
        """
        if template_name in self.template_cache:
            return self.template_cache[template_name]

        template_path = self.template_dir / template_name
        try:
            html_content = template_path.read_text('utf-8')
            self.template_cache[template_name] = html_content
            return html_content
        except FileNotFoundError:
            logger.error(f"Email template not found: {template_path}")
            return ""
        except Exception as e:
            logger.error(f"Error reading email template {template_name}: {e}")
            return ""

    def _send_smtp_message(self, message: MIMEMultipart):
        """
        Sends an email message via SMTP. This operation is blocking and is intended
        to be executed in a background thread or BackgroundTasks.
        """
        try:
            # Create a secure SSL context
            context = ssl.create_default_context()
            if not settings.VALIDATE_CERTS:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                if self.use_credentials:
                    server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.sender_email, message["To"], message.as_string())
            logger.info(f"Email '{message['Subject']}' sent successfully to {message['To']}")
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error while sending email: {e}")
        except Exception as e:
            logger.error(f"An error occurred while sending email: {e}")

    async def send_email_async(
        self,
        subject: str,
        email_to: str,
        template_name: str,
        context: Dict[str, Any],
        background_tasks: BackgroundTasks = None,
    ):
        """
        Asynchronously sends an email using a template.

        Args:
            subject (str): The subject line of the email.
            email_to (str): The recipient's email address.
            template_name (str): The name of the HTML template file (e.g., 'verification.html').
            context (Dict[str, Any]): A dictionary of variables to be passed to the template.
            background_tasks (BackgroundTasks): Optional. A FastAPI BackgroundTasks
                instance to offload the email sending.
        """
        if not settings.EMAIL_ENABLED:
            logger.warning(f"Email sending is disabled. Skipping email to {email_to} for subject: {subject}")
            # For testing/integration, still schedule a no-op task if background_tasks provided
            if background_tasks:
                background_tasks.add_task(lambda: None)
            return
        # Load and render the HTML template
        html_content = self._get_template(template_name)
        if not html_content:
            logger.error(f"Failed to load email template {template_name}")
            return

        for key, value in context.items():
            html_content = html_content.replace(f"{{{{ {key} }}}}", str(value))

        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = self.sender_email
        message["To"] = email_to
        part_html = MIMEText(html_content, "html")
        message.attach(part_html)

        # Always offload to background to avoid blocking request processing.
        # Prefer FastAPI BackgroundTasks when available, else spawn a detached task.
        if background_tasks:
            background_tasks.add_task(self._send_smtp_message, message)
        else:
            # Offload the blocking SMTP send to a thread without blocking the request.
            import asyncio
            async def _offload():
                await run_in_threadpool(self._send_smtp_message, message)
            asyncio.create_task(_offload())

    async def send_verification_email(self, email: str, token: str, background_tasks: BackgroundTasks):
        """Sends a verification email with a unique link."""
        verification_link = f"{settings.API_BASE_URL}/auth/verify?token={token}"
        context = {"verification_link": verification_link}
        await self.send_email_async(
            subject="Verify Your Email Address",
            email_to=email,
            template_name="verification.html",
            context=context,
            background_tasks=background_tasks
        )

    async def send_password_reset_email(self, email: str, token: str, background_tasks: BackgroundTasks):
        """Sends a password reset email with a unique link."""
        reset_link = f"{settings.API_BASE_URL}/auth/reset-password?token={token}"
        context = {"reset_link": reset_link}
        await self.send_email_async(
            subject="Password Reset Request",
            email_to=email,
            template_name="password_reset.html",
            context=context,
            background_tasks=background_tasks
        )

    async def send_new_login_email(self, email: str, background_tasks: BackgroundTasks, context: Dict[str, Any] = None):
        """Sends an email confirming a new login."""
        await self.send_email_async(
            subject="New Login",
            email_to=email,
            template_name="new_login.html",
            context=context if context is not None else {},
            background_tasks=background_tasks
        )

    async def send_mfa_added_email(self, email: str, background_tasks: BackgroundTasks, context: Dict[str, Any] = None):
        """Sends an email confirming a new login."""
        await self.send_email_async(
            subject="MFA Added",
            email_to=email,
            template_name="mfa_added.html",
            context=context if context is not None else {},
            background_tasks=background_tasks
        )

    async def send_mfa_removed_email(self, email: str, background_tasks: BackgroundTasks, context: Dict[str, Any] = None):
        """Sends an email confirming a new login."""
        await self.send_email_async(
            subject="MFA Removed",
            email_to=email,
            template_name="mfa_removed.html",
            context=context if context is not None else {},
            background_tasks=background_tasks
        )

    async def send_mfa_failed_email(self, email: str, background_tasks: BackgroundTasks, context: Dict[str, Any] = None):
        """Sends an email confirming a new login."""
        await self.send_email_async(
            subject="MFA Failed",
            email_to=email,
            template_name="mfa_failed.html",
            context=context if context is not None else {},
            background_tasks=background_tasks
        )

    async def send_new_social_account_connected_email(self, email: str, background_tasks: BackgroundTasks, context: Dict[str, Any] = None):
        """Sends an email confirming a new login."""
        await self.send_email_async(
            subject="New Social Account Connected",
            email_to=email,
            template_name="new_social_account_connected.html",
            context=context if context is not None else {},
            background_tasks=background_tasks
        )

    async def send_password_change_email(self, email: str, background_tasks: BackgroundTasks, context: Dict[str, Any] = None):
        """Sends an email confirming a password change."""
        await self.send_email_async(
            subject="Password Changed",
            email_to=email,
            template_name="password_change.html",
            context=context if context is not None else {},
            background_tasks=background_tasks
        )

    async def send_authorize_confirm_email(self, email: str, authorize_token: str, background_tasks: BackgroundTasks):
        """Sends a link to authorize an action."""
        authorize_link = f"{settings.API_BASE_URL}/auth/authorize?authorize_token={authorize_token}"
        context = {"authorize_link": authorize_link}
        await self.send_email_async(
            subject="Authorize Confirmation",
            email_to=email,
            template_name="authorize_confirm.html",
            context=context,
            background_tasks=background_tasks
        )

    async def send_welcome_email(self, email: str, background_tasks: BackgroundTasks, context: Dict[str, Any] = None):
        """Sends a welcome email to the user after successful registration."""
        await self.send_email_async(
            subject=f"Welcome to {settings.APP_NAME}!",
            email_to=email,
            template_name="welcome.html",
            context=context if context is not None else {},
            background_tasks=background_tasks
        )

    async def send_org_invite_email(self, email: str, token: str, org_name: str, inviter_name: str,
                                    background_tasks: BackgroundTasks):
        """Sends an organization invitation email."""
        join_link = f"{settings.API_BASE_URL}/ui/organizations/join?token={token}"
        context = {
            "join_link": join_link,
            "inviter_name": inviter_name,
            "org_name": org_name,
            "APP_NAME": settings.APP_NAME,
        }
        await self.send_email_async(
            subject="You've been invited to an organization!",
            email_to=email,
            template_name="org_invite.html",
            context=context,
            background_tasks=background_tasks
        )

    async def send_team_invite_email(self, email: str, token: str, team_name: str, inviter_name: str, background_tasks: BackgroundTasks):
        """Sends a team invitation email."""
        join_link = f"{settings.API_BASE_URL}/ui/teams/join?token={token}"
        context = {
            "join_link": join_link,
            "inviter_name": inviter_name,
            "team_name": team_name,
            "APP_NAME": settings.APP_NAME,
        }
        await self.send_email_async(
            subject="You've been invited to a team!",
            email_to=email,
            template_name="team_invite.html",
            context=context,
            background_tasks=background_tasks
        )

    async def send_passwordless_login_email(self, email: str, token: str, background_tasks: BackgroundTasks):
        """Sends a passwordless login email with a unique link."""
        login_link = f"{settings.API_BASE_URL}/auth/passwordless/login?token={token}"
        context = {"login_link": login_link}
        await self.send_email_async(
            subject="Passwordless Login",
            email_to=email,
            template_name="passwordless_login.html",
            context=context,
            background_tasks=background_tasks
        )

email_manager = EmailManager()
