import os
import django
from django.core.mail import send_mail
from django.conf import settings

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nerdslab.settings')
django.setup()

def test_email_connection():
    """Test email connection and sending functionality"""
    print("Email settings:")
    print(f"EMAIL_HOST: {settings.EMAIL_HOST}")
    print(f"EMAIL_PORT: {settings.EMAIL_PORT}")
    print(f"EMAIL_USE_TLS: {settings.EMAIL_USE_TLS}")
    print(f"EMAIL_HOST_USER: {settings.EMAIL_HOST_USER}")
    print(f"DEFAULT_FROM_EMAIL: {settings.DEFAULT_FROM_EMAIL}")
    
    try:
        recipient = "test@example.com"  # Change to a real test email
        subject = "Test Email from NerdsLab API"
        message = "This is a test email to verify the email functionality is working correctly."
        from_email = settings.DEFAULT_FROM_EMAIL
        
        print(f"\nSending test email to {recipient}...")
        send_mail(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=[recipient],
            fail_silently=False,
        )
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")

if __name__ == "__main__":
    test_email_connection() 