#!/bin/bash

echo "Stopping Nginx Load Balancer..."

# Stop nginx process
if [ -f /tmp/nginx-loadbalancer/nginx.pid ]; then
	nginx -s quit -c /tmp/nginx-loadbalancer/nginx_least_time.conf -p /tmp/nginx-loadbalancer/
	echo "Nginx Load Balancer stopped."
else
	echo "Nginx Load Balancer is not running."
fi

# Clean up temporary files
rm -rf /tmp/nginx-loadbalancer
echo "Cleaned up temporary files."
