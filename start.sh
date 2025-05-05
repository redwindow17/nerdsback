#!/bin/bash

# Create necessary directories
mkdir -p logs media staticfiles backups/sqlite

# Set up logging directories with proper permissions
mkdir -p logs
chmod 755 logs
touch logs/auth_service.log logs/email_service.log
chmod 644 logs/auth_service.log logs/email_service.log

# Make backup script executable
chmod +x scripts/backup_sqlite.sh

# Set up SQLite database with proper permissions if we have access
DB_PATH="/var/www/nerdsback/db.sqlite3"
if [ ! -f "$DB_PATH" ]; then
    touch "$DB_PATH"
    if [ $? -eq 0 ]; then
        chmod 600 "$DB_PATH" || echo "Warning: Could not set database permissions. Please ensure correct permissions manually."
    else
        echo "Warning: Could not create database file. Please ensure the file exists with correct permissions."
    fi
fi

# Run migrations
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --noinput

# Apply SQLite optimizations if we have write access to the database
if [ -w "$DB_PATH" ]; then
    echo "Applying SQLite optimizations..."
    python - << EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()
c.execute('PRAGMA journal_mode = WAL')
c.execute('PRAGMA synchronous = NORMAL')
c.execute('PRAGMA temp_store = MEMORY')
c.execute('PRAGMA mmap_size = 268435456')
c.execute('PRAGMA cache_size = -64000')
c.execute('PRAGMA busy_timeout = 30000')
conn.close()
EOF
else
    echo "Warning: Could not apply SQLite optimizations. Database file is not writable."
fi

# Start Gunicorn with SQLite-optimized settings
exec gunicorn nerdslab.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --threads 4 \
    --worker-class gthread \
    --worker-tmp-dir /dev/shm \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --timeout 120 \
    --keepalive 75 \
    --log-level info