# Nginx Overhead Testing

## Usage

### Start Nginx Server
```bash
./start_server.sh
```

### Build Client
```bash
make
```

### Run Load Test
```bash
# Standard test: 16 clients, 625,000 requests each
./nginx_client 16 625000
```

### Stop Nginx Server
```bash
./stop_server.sh
```

## Configuration
- **Port**: 50000
- **Document Root**: /tmp/nginx-server/html
- **Sample File**: index.html (~8KB)
- **Endpoints**: /, /api/, /status
- **Data**: HTTP GET requests to sample HTML
