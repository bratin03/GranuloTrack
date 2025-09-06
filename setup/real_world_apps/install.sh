#!/bin/bash

set -e

echo "Installing real-world applications for GranuloTrack overhead testing..."

# Update package lists
apt-get update

# Install MySQL
echo "Installing MySQL..."
apt-get install -y mysql-server mysql-client libmysqlclient-dev

# Install Nginx
echo "Installing Nginx..."
apt-get install -y nginx

# Install Redis
echo "Installing Redis..."
apt-get install -y redis-server

# Install client tools
apt-get install -y redis-tools libmysqlcppconn-dev

# Create directories
mkdir -p /var/log/granulotrack
mkdir -p /etc/granulotrack

echo "Installation completed."
