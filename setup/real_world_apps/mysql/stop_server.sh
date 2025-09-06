#!/bin/bash

echo "Stopping MySQL server on port 30000..."

# Stop MySQL processes
pkill mysqld 2>/dev/null || true

# Wait a moment for processes to stop
sleep 2

# Check if MySQL is still running
if ss -lnt | grep -q ":30000 "; then
    echo "Warning: MySQL may still be running on port 30000."
else
    echo "MySQL server stopped successfully."
fi
