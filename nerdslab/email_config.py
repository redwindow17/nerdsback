import os
import logging
from django.conf import settings
from django.core.mail import get_connection, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from threading import Thread
import time
from smtplib import SMTPException, SMTPAuthenticationError
from socket import timeout as SocketTimeout

logger = logging.getLogger('email')

def get_email_connection():
    """Get a configured email connection with retry logic"""
    try:
        return get_connection(
            host=settings.EMAIL_HOST,
            port=settings.EMAIL_PORT,
            username=settings.EMAIL_HOST_USER,
            password=settings.EMAIL_HOST_PASSWORD,
            use_tls=settings.EMAIL_USE_TLS,
            timeout=settings.EMAIL_TIMEOUT
        )
    except Exception as e:
        logger.error(f"Failed to create email connection: {str(e)}")
        raise

def send_email_async(subject, to_email, template_name, context, from_email=None):
    """Send email asynchronously with retry logic"""
    if from_email is None:
        from_email = settings.DEFAULT_FROM_EMAIL

    def send():
        try:
            # Render email content
            html_content = render_to_string(template_name, context)
            text_content = strip_tags(html_content)

            # Create email message
            msg = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=from_email,
                to=[to_email],
                connection=get_email_connection()
            )
            msg.attach_alternative(html_content, "text/html")

            # Implement retry mechanism
            for attempt in range(settings.SMTP_MAX_RETRIES):
                try:
                    msg.send()
                    logger.info(f"Email sent successfully to {to_email}")
                    return True
                except SMTPAuthenticationError as e:
                    logger.error(f"SMTP Authentication failed: {str(e)}")
                    raise  # Don't retry on auth failure
                except (SMTPException, SocketTimeout) as e:
                    if attempt < settings.SMTP_MAX_RETRIES - 1:
                        logger.warning(f"Email sending failed (attempt {attempt + 1}): {str(e)}")
                        time.sleep(settings.SMTP_RETRY_DELAY)
                    else:
                        logger.error(f"All email sending attempts failed for {to_email}: {str(e)}")
                        raise
                except Exception as e:
                    logger.error(f"Unexpected error sending email to {to_email}: {str(e)}")
                    raise

        except Exception as e:
            logger.error(f"Error preparing email for {to_email}: {str(e)}")
            raise

    # Start email sending in background
    Thread(target=send).start()

def send_verification_email(user, token):
    """Send verification email to user"""
    try:
        verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token.token}"
        context = {
            'verify_url': verify_url,
            'user': user,
            'expiry_hours': 48,
            'now': time.time()  # For copyright year in template
        }
        
        send_email_async(
            subject='Verify Your NerdsLab Account',
            to_email=user.email,
            template_name='emails/email_verification.html',
            context=context
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {str(e)}")
        raise

def send_password_reset_email(user, token):
    """Send password reset email to user"""
    try:
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token.token}"
        context = {
            'reset_url': reset_url,
            'user': user,
            'expiry_hours': 24,
            'now': time.time()  # For copyright year in template
        }
        
        send_email_async(
            subject='Reset Your NerdsLab Password',
            to_email=user.email,
            template_name='emails/password_reset.html',
            context=context
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
        raise 