#!/usr/bin/env python3
"""
Htop-style Server Monitoring Script for GranuloTrack Load Balancer
Monitors CPU usage using ps command and sends updates to the load balancer via UDP
"""

import json
import logging
import socket
import subprocess
import sys
import time
from typing import List, Dict, Any

class HtopServerMonitor:
    def __init__(self, config_file: str):
        """Initialize the htop server monitor with configuration"""
        self.config = self.load_config(config_file)
        self.server_id = self.config['server_id']
        self.lb_host = self.config['load_balancer']['host']
        self.lb_port = self.config['load_balancer']['port']
        self.source = self.config.get('source', 'htop')
        
        # Monitoring configuration
        self.update_interval_ms = self.config['monitoring'].get('update_interval_ms', 500)
        self.send_interval_ms = self.config['monitoring'].get('send_interval_ms', 2000)
        self.max_samples = self.config['monitoring'].get('max_samples', 20)
        self.process_names = self.config['monitoring'].get('process_names', ['apache2', 'httpd'])
        
        # Setup logging
        self.setup_logging()
        
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        self.logger.info(f"Htop Server Monitor initialized for {self.server_id}")
        self.logger.info(f"Load balancer: {self.lb_host}:{self.lb_port}")
        self.logger.info(f"Update interval: {self.update_interval_ms}ms, Send interval: {self.send_interval_ms}ms")
        self.logger.info(f"Process names: {self.process_names}")
    
    def setup_logging(self):
        """Setup logging configuration"""
        import os
        
        # Use full server name for log file (e.g., "server1" -> "server1.log")
        log_file = f"/tmp/htop_apache/{self.server_id}.log"
        
        # Create logs directory if it doesn't exist
        os.makedirs("/tmp/htop_apache", exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file)
            ]
        )
        self.logger = logging.getLogger(f"HtopMonitor-{self.server_id}")
    
    def load_config(self, config_file: str) -> Dict[str, Any]:
        """Load server configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Configuration file '{config_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in configuration file: {e}")
            sys.exit(1)
    
    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            # Build process name list for ps command
            process_list = ",".join(self.process_names)
            
            # Run ps to get CPU usage for specified processes
            result = subprocess.run(
                ["/usr/bin/ps", "-C", process_list, "-o", "%cpu="],
                capture_output=True, text=True, timeout=5
            )
            
            cpu_lines = result.stdout.strip().splitlines()
            if not cpu_lines or not cpu_lines[0].strip():
                return 0.0
            
            # Filter out empty lines and convert to float
            cpu_values = []
            for line in cpu_lines:
                line = line.strip()
                if line:
                    try:
                        cpu_values.append(float(line))
                    except ValueError:
                        continue
            
            if not cpu_values:
                return 0.0
            
            # Calculate average CPU usage
            avg_cpu = sum(cpu_values) / len(cpu_values)
            return round(avg_cpu, 2)
            
        except subprocess.TimeoutExpired:
            self.logger.warning("ps command timed out")
            return 0.0
        except Exception as e:
            self.logger.warning(f"Error getting CPU usage: {e}")
            return 0.0
    
    def collect_utilization_samples(self, duration_ms: int) -> List[float]:
        """Collect CPU utilization samples over specified duration"""
        samples = []
        start_time = time.time()
        end_time = start_time + (duration_ms / 1000.0)
        
        while time.time() < end_time:
            cpu_usage = self.get_cpu_usage()
            samples.append(cpu_usage)
            
            # Sleep for update_interval_ms milliseconds
            time.sleep(self.update_interval_ms / 1000.0)
        
        return samples
    
    def send_update(self, utilizations: List[float], average_utilization: float):
        """Send utilization update to load balancer via UDP"""
        timestamp = int(time.time())
        
        # Create update message
        update_data = {
            "server_id": self.server_id,
            "average_utilization": str(average_utilization),
            "source": self.source,
            "timestamp": timestamp,
            "utilizations": [str(u) for u in utilizations]
        }
        
        # Convert to JSON
        message = json.dumps(update_data)
        
        try:
            # Send UDP message
            self.sock.sendto(message.encode('utf-8'), (self.lb_host, self.lb_port))
            self.logger.info(f"Sent update: {self.server_id} avg={average_utilization:.2f}% "
                           f"(samples: {len(utilizations)})")
        except Exception as e:
            self.logger.error(f"Error sending update: {e}")
    
    def run(self):
        """Main monitoring loop"""
        self.logger.info(f"Starting htop monitoring for server {self.server_id}...")
        self.logger.info("Press Ctrl+C to stop")
        
        try:
            while True:
                # Collect samples over send_interval_ms duration
                utilizations = self.collect_utilization_samples(self.send_interval_ms)
                
                if utilizations:
                    # Calculate average
                    average_utilization = sum(utilizations) / len(utilizations)
                    
                    # Send update to load balancer
                    self.send_update(utilizations, average_utilization)
                else:
                    self.logger.warning("No CPU samples collected")
                
        except KeyboardInterrupt:
            self.logger.info(f"Stopping htop monitor for server {self.server_id}")
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {e}")
        finally:
            self.sock.close()

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 htop_server_monitor.py <config_file>")
        print("Example: python3 htop_server_monitor.py config/server/server1.json")
        sys.exit(1)
    
    config_file = sys.argv[1]
    monitor = HtopServerMonitor(config_file)
    monitor.run()

if __name__ == "__main__":
    main()
