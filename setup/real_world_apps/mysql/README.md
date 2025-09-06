# MySQL Overhead Testing

## Usage

### Start MySQL Server
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
./mysql_client 16 625000
```

### Stop MySQL Server
```bash
./stop_server.sh
```

## Configuration
- **Port**: 30000
- **Database**: testdb
- **User**: testuser
- **Table**: key_value_table (key_data, value_data)
- **Data**: Random strings (keys: 512-1024 chars, values: 1024-4096 chars)

