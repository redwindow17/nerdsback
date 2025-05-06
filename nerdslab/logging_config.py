import os
import logging.config
from django.conf import settings
import tempfile
import stat

def configure_logging():
    """Configure logging for the application"""
    # Get log file path from environment or use a default in the temp directory
    log_file = os.environ.get('LOG_FILE', os.path.join(tempfile.gettempdir(), 'nerdslab_backend', 'app.log'))
    
    # Create log directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    try:
        os.makedirs(log_dir, exist_ok=True)
        
        # Check if we can write to the log file
        if os.path.exists(log_file):
            # Check if we have write permissions
            if not os.access(log_file, os.W_OK):
                print(f"Warning: No write permission for log file {log_file}")
                log_file = os.path.join(tempfile.gettempdir(), 'nerdslab_backend.log')
        else:
            # Try to create the file to check permissions
            try:
                with open(log_file, 'a'):
                    pass
            except (IOError, PermissionError):
                print(f"Warning: Cannot create log file {log_file}")
                log_file = os.path.join(tempfile.gettempdir(), 'nerdslab_backend.log')
                
    except Exception as e:
        print(f"Warning: Could not create log directory {log_dir}: {e}")
        # Fallback to temp directory if we can't create the specified directory
        log_file = os.path.join(tempfile.gettempdir(), 'nerdslab_backend.log')
    
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
                'style': '{',
            },
            'simple': {
                'format': '{levelname} {message}',
                'style': '{',
            },
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
            'file': {
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': log_file,
                'maxBytes': 10485760,  # 10MB
                'backupCount': 5,
                'formatter': 'verbose',
                'encoding': 'utf-8',
            },
        },
        'loggers': {
            'django': {
                'handlers': ['console', 'file'],
                'level': 'INFO',
                'propagate': True,
            },
            'accounts': {
                'handlers': ['console', 'file'],
                'level': 'INFO',
                'propagate': True,
            },
            'nerdslab': {
                'handlers': ['console', 'file'],
                'level': 'INFO',
                'propagate': True,
            },
        },
        'root': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
    }
    
    try:
        logging.config.dictConfig(LOGGING)
        # Log successful configuration
        logger = logging.getLogger(__name__)
        logger.info(f"Logging configured successfully. Log file: {log_file}")
    except Exception as e:
        print(f"Warning: Could not configure logging: {e}")
        # Fallback to basic console logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(levelname)s %(asctime)s %(message)s',
            handlers=[logging.StreamHandler()]
        ) 