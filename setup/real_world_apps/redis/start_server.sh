#!/bin/bash

set -e

echo "Starting Redis server on custom port..."

# Check if Redis is already running on port 40000
if ss -lnt | grep -q ":40000 "; then
    echo "Redis is already running on 127.0.0.1:40000."
    # Test Redis connection
    redis-cli -p 40000 ping
    echo "Redis instance is ready."
    exit 0
fi

# Stop any existing Redis processes
pkill redis-server 2>/dev/null || true

# Wait a moment for processes to stop
sleep 1

# Create Redis server directory
mkdir -p /tmp/redis-server/data

# Copy Redis config
cp redis_test.conf /tmp/redis-server/redis_test.conf

# Start Redis with custom config
echo "Starting Redis on 127.0.0.1:40000..."
redis-server /tmp/redis-server/redis_test.conf &

# Give the server a moment to start
sleep 2

# Verify that Redis is listening on the specified port
if ss -lnt | grep -q ":40000 "; then
    echo "Redis instance successfully started on 127.0.0.1:40000."
    # Test Redis connection
    redis-cli -p 40000 ping
else
    echo "Error: Redis instance failed to start on 127.0.0.1:40000."
    exit 1
fi
 