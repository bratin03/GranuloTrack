#!/bin/bash

set -e

echo "Starting MySQL server on custom port..."

# Check if MySQL is already running
if ss -lnt | grep -q ":30000 "; then
    echo "MySQL is already running on port 30000."
    exit 0
fi

# Create MySQL data directory
mkdir -p /tmp/mysql-server/data
mkdir -p /tmp/mysql-server/logs

# Initialize MySQL data directory if needed
if [ ! -f /tmp/mysql-server/data/mysql/user.frm ]; then
    echo "Initializing MySQL data directory..."
    # Clean up any partial initialization
    rm -rf /tmp/mysql-server/data/*
    # Create MySQL config with current user
    cp mysql_test.conf /tmp/mysql-server/mysql_test.cnf
    sed -i "s/user = current_user/user = $(whoami)/" /tmp/mysql-server/mysql_test.cnf
    # Initialize using our custom config
    mysqld --defaults-file=/tmp/mysql-server/mysql_test.cnf --initialize-insecure
fi

# Create MySQL config with current user (if not already done during initialization)
if [ ! -f /tmp/mysql-server/mysql_test.cnf ]; then
    cp mysql_test.conf /tmp/mysql-server/mysql_test.cnf
    sed -i "s/user = current_user/user = $(whoami)/" /tmp/mysql-server/mysql_test.cnf
fi

# Start MySQL with custom config
echo "Starting MySQL on 127.0.0.1:30000..."
mysqld --defaults-file=/tmp/mysql-server/mysql_test.cnf &

# Give the server a moment to start
sleep 5

# Set root password and create test database
mysql -u root -S /tmp/mysql-server/mysql.sock -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'testpass';" 2>/dev/null || true
mysql -u root -ptestpass -S /tmp/mysql-server/mysql.sock -e "CREATE DATABASE IF NOT EXISTS testdb;" 2>/dev/null || true
mysql -u root -ptestpass -S /tmp/mysql-server/mysql.sock -e "CREATE USER IF NOT EXISTS 'testuser'@'localhost' IDENTIFIED BY 'testpass';" 2>/dev/null || true
mysql -u root -ptestpass -S /tmp/mysql-server/mysql.sock -e "GRANT ALL PRIVILEGES ON testdb.* TO 'testuser'@'localhost';" 2>/dev/null || true
mysql -u root -ptestpass -S /tmp/mysql-server/mysql.sock -e "FLUSH PRIVILEGES;" 2>/dev/null || true

# Verify that MySQL is listening on the specified port
if ss -lnt | grep -q ":30000 "; then
    echo "MySQL instance successfully started on 127.0.0.1:30000."
    # Test MySQL connection
    mysql -u testuser -ptestpass -S /tmp/mysql-server/mysql.sock -e "SELECT 1;" 2>/dev/null
else
    echo "Error: MySQL instance failed to start on 127.0.0.1:3307."
    exit 1
fi
