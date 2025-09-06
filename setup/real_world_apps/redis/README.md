# Redis Overhead Testing

## Usage

### Start Redis Server
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
./redis_client 16 625000
```

### Stop Redis Server
```bash
./stop_server.sh
```

## Configuration
- **Port**: 40000
- **Data Directory**: /tmp/redis-server/data
- **Max Memory**: 256MB
- **Operations**: SET commands only
- **Data**: Random strings (keys: 512-1024 chars, values: 1024-4096 chars)
