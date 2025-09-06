#!/bin/bash

echo "Stopping Redis server on port 40000..."

# Stop Redis processes
pkill redis-server 2>/dev/null || true

# Wait a moment for processes to stop
sleep 1

# Check if Redis is still running
if ss -lnt | grep -q ":40000 "; then
    echo "Warning: Redis may still be running on port 40000."
else
    echo "Redis server stopped successfully."
fi
