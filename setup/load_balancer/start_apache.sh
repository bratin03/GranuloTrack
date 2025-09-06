#!/bin/bash

# Start Apache server on specific IP and port
# Usage: ./start_apache.sh <ip> <port>
# Example: ./start_apache.sh 127.0.0.1 10021

if [ $# -ne 2 ]; then
	echo "Usage: $0 <ip> <port>"
	exit 1
fi

IP=$1
PORT=$2

# Directories
DOC_ROOT="/tmp/apache_${IP}_${PORT}"
RUNTIME_DIR="/tmp/apache_runtime_${IP}_${PORT}"
mkdir -p "$DOC_ROOT" "$RUNTIME_DIR"

# Create simple index.html
cat >"$DOC_ROOT/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Apache Server $IP:$PORT</title>
</head>
<body>
    <h1>Hello World</h1>
    <p>Server: $IP:$PORT</p>
    <p>Time: $(date)</p>
</body>
</html>
EOF

# Create simple text response
cat >"$DOC_ROOT/api.txt" <<EOF
Hello World from server at $IP:$PORT
Timestamp: $(date)
EOF

# Pick correct mime.types path
if [ -f /etc/mime.types ]; then
	MIME_TYPES="/etc/mime.types"
elif [ -f /etc/apache2/mime.types ]; then
	MIME_TYPES="/etc/apache2/mime.types"
else
	MIME_TYPES="$RUNTIME_DIR/mime.types"
	echo "text/html   html" >"$MIME_TYPES"
	echo "text/plain  txt" >>"$MIME_TYPES"
fi

# Create temporary Apache configuration file
CONFIG_FILE="/tmp/apache_config_${IP}_${PORT}.conf"
cat >"$CONFIG_FILE" <<EOF
ServerRoot "$RUNTIME_DIR"
Listen $IP:$PORT
ServerName $IP

# Load required modules (skip built-ins)
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule authz_host_module /usr/lib/apache2/modules/mod_authz_host.so

TypesConfig $MIME_TYPES
DirectoryIndex index.html

PidFile $RUNTIME_DIR/httpd.pid
ErrorLog /dev/stderr

# Access log in combined format
LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined
CustomLog /dev/stdout combined

<VirtualHost $IP:$PORT>
    DocumentRoot $DOC_ROOT
    
    <Directory $DOC_ROOT>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
EOF

# Start Apache with custom configuration
trap "apache2 -k stop -f $CONFIG_FILE; rm -rf $CONFIG_FILE $RUNTIME_DIR" EXIT
apache2 -D FOREGROUND -f "$CONFIG_FILE"
