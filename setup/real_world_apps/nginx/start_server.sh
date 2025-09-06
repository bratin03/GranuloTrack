#!/bin/bash

set -e

echo "Starting Nginx server on custom port..."

# Check if Nginx is already running
if ss -lnt | grep -q ":50000 "; then
    echo "Nginx is already running on port 50000."
    exit 0
fi

# Create test directory structure
mkdir -p /tmp/nginx-server/html
mkdir -p /tmp/nginx-server/logs

# Copy sample HTML as index page
cp sample.html /tmp/nginx-server/html/index.html

# Copy Nginx config
cp nginx_test.conf /tmp/nginx-server/nginx_test.conf

# Clean old logs to avoid confusion
: > /tmp/nginx-server/error.log
: > /tmp/nginx-server/access.log

# Test configuration with custom prefix
nginx -t -c /tmp/nginx-server/nginx_test.conf -p /tmp/nginx-server/

# Start Nginx with custom config + prefix
echo "Starting Nginx on 127.0.0.1:50000..."
nginx -c /tmp/nginx-server/nginx_test.conf -p /tmp/nginx-server/

# Give the server a moment to start
sleep 2

# Verify that Nginx is listening on the specified port
if ss -lnt | grep -q ":50000 "; then
    echo "Nginx instance successfully started on 127.0.0.1:50000."
    # Test Nginx connection
    curl -s http://127.0.0.1:50000/status
else
    echo "Error: Nginx instance failed to start on 127.0.0.1:50000."
    exit 1
fi
