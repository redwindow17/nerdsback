#!/bin/bash

# Create necessary directories
mkdir -p logs media staticfiles backups/sqlite

# Set up SQLite database with proper permissions
touch db.sqlite3
chmod 600 db.sqlite3

# Set up logging directories with proper permissions
mkdir -p logs
chmod 755 logs
touch logs/auth_service.log logs/email_service.log
chmod 644 logs/auth_service.log logs/email_service.log

# Make backup script executable
chmod +x scripts/backup_sqlite.sh

# Run migrations
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --noinput

# Start Gunicorn with SQLite optimizations
# Using fewer workers and threads to prevent SQLite locks
gunicorn nerdslab.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 2 \
    --threads 2 \
    --worker-class gthread \
    --timeout 120 \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --access-logfile logs/gunicorn-access.log \
    --error-logfile logs/gunicorn-error.log \
    --capture-output \
    --enable-stdio-inheritance