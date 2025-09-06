#!/usr/bin/env python3
"""
CorePulse Server Monitoring Script for GranuloTrack Load Balancer
Uses CorePulse eBPF tracer for detailed CPU burst analysis and sends updates to load balancer
"""

import json
import logging
import socket
import sys
import time
from typing import List, Dict, Any
from collections import deque

# Import CorePulse from the src directory
sys.path.append('../src')
from CorePulse import CorePulse

class CorePulseServerMonitor:
    def __init__(self, config_file: str):
        """Initialize the CorePulse server monitor with configuration"""
        self.config = self.load_config(config_file)
        self.server_id = self.config['server_id']
        self.lb_host = self.config['load_balancer']['host']
        self.lb_port = self.config['load_balancer']['port']
        self.source = self.config.get('source', 'corepulse')
        
        # Monitoring configuration
        self.update_interval_ms = self.config['monitoring'].get('update_interval_ms', 500)
        self.send_interval_ms = self.config['monitoring'].get('send_interval_ms', 2000)
        self.max_samples = self.config['monitoring'].get('max_samples', 20)
        self.process_patterns = self.config['monitoring'].get('process_patterns', ['apache2', 'httpd'])
        
        # Setup logging
        self.setup_logging()
        
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Initialize CorePulse tracer
        self.pulse = None
        self.init_corepulse()
        
        # Event collection
        self.event_buffer = deque(maxlen=self.max_samples)
        self.last_send_time = time.time()
        
        self.logger.info(f"CorePulse Server Monitor initialized for {self.server_id}")
        self.logger.info(f"Load balancer: {self.lb_host}:{self.lb_port}")
        self.logger.info(f"Update interval: {self.update_interval_ms}ms, Send interval: {self.send_interval_ms}ms")
        self.logger.info(f"Process patterns: {self.process_patterns}")
    
    def setup_logging(self):
        """Setup logging configuration"""
        import os
        
        # Use full server name for log file (e.g., "server1" -> "server1.log")
        log_file = f"/tmp/corepulse_apache/{self.server_id}.log"
        
        # Create logs directory if it doesn't exist
        os.makedirs("/tmp/corepulse_apache", exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file)
            ]
        )
        self.logger = logging.getLogger(f"CorePulseMonitor-{self.server_id}")
    
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
    
    def init_corepulse(self):
        """Initialize CorePulse tracer with process patterns"""
        try:
            self.pulse = CorePulse(
                process_patterns=self.process_patterns,
                num_poll_threads=2,  # Optimized for server monitoring
                queue_size=5000,
                ringbuf_size=256
            )
            self.logger.info(f"CorePulse initialized with patterns: {self.process_patterns}")
        except Exception as e:
            self.logger.error(f"Failed to initialize CorePulse: {e}")
            sys.exit(1)
    
    def calculate_burst_durations_from_events(self, events: List[Dict]) -> List[float]:
        """Extract CPU burst durations from CorePulse events (in nanoseconds)"""
        if not events:
            return []
        
        # Extract burst durations from events (time field is in nanoseconds)
        burst_durations = []
        for event in events:
            duration_ns = event.get('time', 0)
            if duration_ns > 0:
                # Convert nanoseconds to milliseconds for easier handling
                duration_ms = duration_ns / 1e6
                burst_durations.append(duration_ms)
        
        self.logger.debug(f"Extracted {len(burst_durations)} burst durations from {len(events)} events")
        return burst_durations
    
    def send_update(self, burst_durations: List[float], average_duration: float):
        """Send burst duration update to load balancer via UDP"""
        timestamp = int(time.time())
        
        # Create update message with burst durations (not percentages)
        update_data = {
            "server_id": self.server_id,
            "average_utilization": str(average_duration),  # This will be burst duration in ms
            "source": self.source,
            "timestamp": timestamp,
            "utilizations": [str(d) for d in burst_durations]  # Burst durations in ms
        }
        
        # Convert to JSON
        message = json.dumps(update_data)
        
        try:
            # Send UDP message
            self.sock.sendto(message.encode('utf-8'), (self.lb_host, self.lb_port))
            self.logger.info(f"Sent update: {self.server_id} avg_burst={average_duration:.2f}ms "
                           f"(samples: {len(burst_durations)})")
        except Exception as e:
            self.logger.error(f"Error sending update: {e}")
    
    def should_send_update(self) -> bool:
        """Check if it's time to send an update"""
        current_time = time.time()
        time_elapsed = (current_time - self.last_send_time) * 1000  # Convert to ms
        
        # Send if either time interval or sample count reached
        return (time_elapsed >= self.send_interval_ms or 
                len(self.event_buffer) >= self.max_samples)
    
    def run(self):
        """Main monitoring loop"""
        self.logger.info(f"Starting CorePulse monitoring for server {self.server_id}...")
        self.logger.info("Press Ctrl+C to stop")
        
        try:
            for event in self.pulse.stream_events():
                # Add event to buffer
                self.event_buffer.append(event)
                
                # Check if we should send an update
                if self.should_send_update() and self.event_buffer:
                    # Extract burst durations from recent events
                    recent_events = list(self.event_buffer)
                    burst_durations = self.calculate_burst_durations_from_events(recent_events)
                    
                    if burst_durations:
                        # Calculate average burst duration
                        average_duration = sum(burst_durations) / len(burst_durations)
                        
                        # Send update to load balancer
                        self.send_update(burst_durations, average_duration)
                        
                        # Clear buffer and update timestamp
                        self.event_buffer.clear()
                        self.last_send_time = time.time()
                    else:
                        self.logger.warning("No burst duration data to send")
                
        except KeyboardInterrupt:
            self.logger.info(f"Stopping CorePulse monitor for server {self.server_id}")
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources"""
        try:
            if self.pulse:
                self.pulse.stop()
                self.logger.info("CorePulse stopped")
            self.sock.close()
            self.logger.info("Socket closed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 corepulse_server_monitor.py <config_file>")
        print("Example: python3 corepulse_server_monitor.py config/server/server1.json")
        sys.exit(1)
    
    config_file = sys.argv[1]
    monitor = CorePulseServerMonitor(config_file)
    monitor.run()

if __name__ == "__main__":
    main()
