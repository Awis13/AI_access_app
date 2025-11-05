#!/bin/bash

# Setup script for web-app-access log rotation
# This script should be run on the host system (not inside Docker container)

set -e

echo "Setting up log rotation for web-app-access..."

# Create the log directory if it doesn't exist
sudo mkdir -p /var/log/web-app-access
sudo chmod 755 /var/log/web-app-access

# Copy the logrotate configuration
sudo cp web-app-access.logrotate /etc/logrotate.d/web-app-access

# Test the logrotate configuration
sudo logrotate -d /etc/logrotate.d/web-app-access

echo "Log rotation setup complete!"
echo ""
echo "Configuration details:"
echo "- Logs will be stored in: /var/log/web-app-access/"
echo "- Daily rotation with 30 day retention"
echo "- Size-based rotation at 10MB with 5 backups"
echo "- Automatic compression of rotated logs"
echo ""
echo "To manually rotate logs: sudo logrotate -f /etc/logrotate.d/web-app-access"
echo "To check rotation status: sudo logrotate -d /etc/logrotate.d/web-app-access"
