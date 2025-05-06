import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/email_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def test_smtp_connection():
    """Test SMTP connection to Zoho"""
    try:
        # Get SMTP settings from environment
        smtp_host = os.getenv('EMAIL_HOST', 'smtp.zoho.in')
        smtp_port = int(os.getenv('EMAIL_PORT', '587'))
        smtp_user = os.getenv('EMAIL_HOST_USER', 'no-reply@nerdslab.in')
        smtp_password = os.getenv('EMAIL_HOST_PASSWORD', 'dtaK8xf&')
        
        logger.info(f"Testing SMTP connection to {smtp_host}:{smtp_port}")
        
        # Create SMTP connection
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=60)
        server.set_debuglevel(1)  # Enable debug output
        
        # Start TLS
        logger.info("Starting TLS connection...")
        server.starttls()
        
        # Login
        logger.info(f"Attempting login with user: {smtp_user}")
        server.login(smtp_user, smtp_password)
        
        logger.info("SMTP connection successful!")
        return server
    except Exception as e:
        logger.error(f"SMTP connection failed: {str(e)}")
        raise

def test_send_email():
    """Test sending an email through Zoho SMTP"""
    try:
        # Get email settings
        smtp_host = os.getenv('EMAIL_HOST', 'smtp.zoho.in')
        smtp_port = int(os.getenv('EMAIL_PORT', '587'))
        smtp_user = os.getenv('EMAIL_HOST_USER', 'no-reply@nerdslab.in')
        smtp_password = os.getenv('EMAIL_HOST_PASSWORD', 'dtaK8xf&')
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = smtp_user  # Send to self for testing
        msg['Subject'] = 'Test Email from NerdsLab Backend'
        
        # Add body
        body = """
        This is a test email from the NerdsLab Backend.
        
        If you're receiving this, the email configuration is working correctly.
        
        Test Details:
        - SMTP Host: {host}
        - SMTP Port: {port}
        - SMTP User: {user}
        
        Best regards,
        NerdsLab System
        """.format(host=smtp_host, port=smtp_port, user=smtp_user)
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Create SMTP connection
        server = test_smtp_connection()
        
        # Send email
        logger.info("Sending test email...")
        server.send_message(msg)
        logger.info("Test email sent successfully!")
        
        # Close connection
        server.quit()
        
    except Exception as e:
        logger.error(f"Failed to send test email: {str(e)}")
        raise

if __name__ == '__main__':
    try:
        logger.info("Starting email configuration test...")
        
        # Test SMTP connection
        test_smtp_connection()
        
        # Test sending email
        test_send_email()
        
        logger.info("All email tests completed successfully!")
        
    except Exception as e:
        logger.error(f"Email test failed: {str(e)}")
        raise 