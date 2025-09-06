#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <random>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

class RedisClient {
private:
  std::string host;
  int port;
  std::atomic<int> requests{0};
  std::atomic<int> errors{0};

public:
  RedisClient(const std::string &h = "127.0.0.1", int p = 40000)
      : host(h), port(p) {}

  int createSocket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
      return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
      close(sock);
      return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
        0) {
      close(sock);
      return -1;
    }

    return sock;
  }

  bool sendCommand(const std::string &command) {
    int sock = createSocket();
    if (sock < 0) {
      errors++;
      return false;
    }

    ssize_t sent = send(sock, command.c_str(), command.length(), 0);
    if (sent < 0) {
      close(sock);
      errors++;
      return false;
    }

    char buffer[1024];
    ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    close(sock);

    if (received > 0) {
      buffer[received] = '\0';
      std::string response(buffer);
      if (response[0] == '+' || response[0] == '$' || response[0] == ':') {
        requests++;
        return true;
      }
    }

    errors++;
    return false;
  }

  std::string generateRandomString(int min_length, int max_length) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> len_dist(0, 1);
    static std::uniform_int_distribution<> char_dist(32,
                                                     126); // printable ASCII

    int length = min_length + len_dist(gen) % (max_length - min_length + 1);
    std::string result;
    result.reserve(length);

    for (int i = 0; i < length; ++i) {
      result += static_cast<char>(char_dist(gen));
    }

    return result;
  }

  bool setCommand() {
    // Generate random key (512-1024 characters)
    std::string key = generateRandomString(512, 1024);

    // Generate random value (1024-4096 characters)
    std::string value = generateRandomString(1024, 4096);

    std::string command =
        "*3\r\n$3\r\nSET\r\n$" + std::to_string(key.length()) + "\r\n" + key +
        "\r\n$" + std::to_string(value.length()) + "\r\n" + value + "\r\n";

    return sendCommand(command);
  }

  bool getCommand() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                         now.time_since_epoch())
                         .count();

    std::string key = "test_key_" + std::to_string(timestamp % 1000);

    std::string command = "*2\r\n$3\r\nGET\r\n$" +
                          std::to_string(key.length()) + "\r\n" + key + "\r\n";

    return sendCommand(command);
  }

  bool pingCommand() {
    std::string command = "*1\r\n$4\r\nPING\r\n";
    return sendCommand(command);
  }

  void worker(int num_requests) {
    for (int i = 0; i < num_requests; ++i) {
      setCommand();
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  int getRequests() const { return requests.load(); }
  int getErrors() const { return errors.load(); }
};

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cout << "Usage: " << argv[0] << " <num_clients> <requests_per_client>"
              << std::endl;
    return 1;
  }

  int num_clients = std::atoi(argv[1]);
  int requests_per_client = std::atoi(argv[2]);

  RedisClient client;

  std::cout << "Starting " << num_clients << " clients, each sending "
            << requests_per_client << " requests..." << std::endl;

  auto start_time = std::chrono::steady_clock::now();

  std::vector<std::thread> threads;
  for (int i = 0; i < num_clients; ++i) {
    threads.emplace_back(&RedisClient::worker, &client, requests_per_client);
  }

  for (auto &thread : threads) {
    thread.join();
  }

  auto end_time = std::chrono::steady_clock::now();
  auto total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
      end_time - start_time);

  std::cout << "Test completed in " << std::fixed << std::setprecision(20)
            << total_time.count() / 1000000000.0 << " seconds" << std::endl;
  std::cout << "Total requests: " << client.getRequests() << std::endl;
  std::cout << "Total errors: " << client.getErrors() << std::endl;
  std::cout << "Requests per second: " << std::fixed << std::setprecision(20)
            << (client.getRequests() * 1000000000.0 / total_time.count())
            << std::endl;

  return 0;
}
