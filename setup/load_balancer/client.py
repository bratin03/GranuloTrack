#!/usr/bin/env python3
"""
Simple HTTP client for load balancer testing.
Sends requests to the load balancer and displays responses.
"""

import socket
import sys
import time


class SimpleHTTPClient:
    def __init__(self, host="127.0.0.1", port=10000):
        self.host = host
        self.port = port

    def send_request(self, path="/"):
        """Send HTTP request to load balancer"""
        try:
            # Create socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)  # 5 second timeout

            # Connect to load balancer
            client_socket.connect((self.host, self.port))

            # Create HTTP request
            request = f"""GET {path} HTTP/1.1
Host: {self.host}:{self.port}
User-Agent: SimpleHTTPClient/1.0
Connection: close

"""

            # Send request
            client_socket.send(request.encode("utf-8"))

            # Receive response
            response = b""
            while True:
                chunk = client_socket.recv(1024)
                if not chunk:
                    break
                response += chunk

            # Parse response
            response_str = response.decode("utf-8")
            lines = response_str.split("\n")

            # Extract status line
            status_line = lines[0] if lines else "No response"

            # Extract headers and body
            body_start = response_str.find("\r\n\r\n")
            if body_start != -1:
                body = response_str[body_start + 4 :]
            else:
                body = "No body"

            # Extract X-Server header if present
            server_header = None
            for line in lines:
                if line.startswith("X-Server:"):
                    server_header = line.split(":", 1)[1].strip()
                    break

            return {
                "status": status_line,
                "body": body.strip(),
                "server": server_header,
                "full_response": response_str,
            }

        except socket.timeout:
            return {"error": "Connection timeout"}
        except ConnectionRefusedError:
            return {"error": "Connection refused - is the load balancer running?"}
        except Exception as e:
            return {"error": f"Connection error: {e}"}
        finally:
            try:
                client_socket.close()
            except:
                pass


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 client.py <path> [count]")
        print("Example: python3 client.py / 5")
        print("Example: python3 client.py /index.html 5")
        print("Example: python3 client.py /api.txt 5")
        sys.exit(1)

    path = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    client = SimpleHTTPClient()

    print(f"Sending {count} request(s) to load balancer at 127.0.0.1:10000")
    print(f"Path: {path}")
    print("-" * 50)

    for i in range(count):
        print(f"\nRequest {i+1}:")
        result = client.send_request(path)

        if "error" in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Status: {result['status']}")
            if result["server"]:
                print(f"Server: {result['server']}")
            print(f"Body: {result['body']}")

        if count > 1 and i < count - 1:
            time.sleep(0.5)  # Small delay between requests


if __name__ == "__main__":
    main()
