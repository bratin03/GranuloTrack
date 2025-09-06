#!/bin/bash

set -e

NGINX_PREFIX="/tmp/nginx-loadbalancer"
NGINX_CONF="$NGINX_PREFIX/nginx_least_time.conf"
PORT=10000

# Check if Nginx is already running on port $PORT
if ss -lnt | grep -q ":$PORT "; then
	echo "Nginx already running on port $PORT."
	exit 0
fi

# Create nginx load balancer directory structure
mkdir -p "$NGINX_PREFIX/logs"

# Copy nginx config
cp nginx_least_time.conf "$NGINX_CONF"

# Clean old logs
: >"$NGINX_PREFIX/error.log"
: >"$NGINX_PREFIX/access.log"

# Test configuration
nginx -t -c "$NGINX_CONF" -p "$NGINX_PREFIX/"

# Start Nginx with custom config + prefix
nginx -c "$NGINX_CONF" -p "$NGINX_PREFIX/"

# Give the server a moment to start
sleep 2

# Verify that Nginx is listening on the specified port
if ss -lnt | grep -q ":$PORT "; then
	echo "Nginx Load Balancer (Plus) started on 127.0.0.1:$PORT"
	echo ""
	echo "=== Nginx Load Balancer Info ==="
	echo "Load Balancer: http://127.0.0.1:$PORT"
	echo "Health Check: http://127.0.0.1:$PORT/health"
	echo "Status:       http://127.0.0.1:$PORT/status"
	echo "Backend Servers:"
	echo "  - 127.0.0.1:10021"
	echo "  - 127.0.0.1:10022"
	echo "  - 127.0.0.1:10023"
	echo "  - 127.0.0.1:10024"
	echo ""
	echo "Strategy: least_time (NGINX Plus - response time based)"
	echo ""
	echo "Testing health endpoint..."
	curl -s "http://127.0.0.1:$PORT/health" || echo "Health check failed"
	echo ""
else
	echo "Error: Nginx Load Balancer failed to start on 127.0.0.1:$PORT."
	exit 1
fi
