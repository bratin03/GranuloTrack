#!/bin/bash

echo "Stopping Nginx server on port 50000..."

# Stop Nginx processes
pkill nginx 2>/dev/null || true

# Wait a moment for processes to stop
sleep 1

# Check if Nginx is still running
if ss -lnt | grep -q ":50000 "; then
    echo "Warning: Nginx may still be running on port 50000."
else
    echo "Nginx server stopped successfully."
fi
