#include "../include/load_balancer.h"
#include <arpa/inet.h>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

// Forward declarations for libev structures
struct ev_loop;
struct ev_io;
struct ev_timer;

namespace GranuloTrack {

LoadBalancer::LoadBalancer(const LoadBalancerConfig &config)
    : config_(config), running_(false), total_requests_(0),
      active_connections_(0), tcp_client_socket_(-1), udp_update_socket_(-1) {

  server_manager_ = std::make_shared<ServerManager>(config);
  connection_pool_ = std::make_shared<ConnectionPool>(config);
  http_handler_ =
      std::make_shared<HttpHandler>(server_manager_, connection_pool_);

  // Initialize event loop
  loop_ = ev_default_loop(0);

  // Initialize watchers
  ev_io_init(&tcp_client_watcher_, onTcpClientConnection, -1, EV_READ);
  ev_io_init(&udp_update_watcher_, onUdpUpdateConnection, -1, EV_READ);
  ev_timer_init(&health_check_timer_, onHealthCheck,
                config_.health_check_interval, config_.health_check_interval);
}

LoadBalancer::~LoadBalancer() {
  stop();
  closeSockets();
}

bool LoadBalancer::start() {
  if (running_) {
    return true;
  }

  if (!initializeSockets()) {
    std::cerr << "Failed to initialize sockets" << std::endl;
    return false;
  }

  // Set up event watchers
  ev_io_set(&tcp_client_watcher_, tcp_client_socket_, EV_READ);
  ev_io_set(&udp_update_watcher_, udp_update_socket_, EV_READ);

  // Set data pointers for callbacks
  tcp_client_watcher_.data = this;
  udp_update_watcher_.data = this;
  health_check_timer_.data = this;

  ev_io_start(loop_, &tcp_client_watcher_);
  ev_io_start(loop_, &udp_update_watcher_);
  ev_timer_start(loop_, &health_check_timer_);

  // Initialize connection pool
  connection_pool_->initializePool();

  running_ = true;

  spdlog::info("Load balancer started on {}:{}", config_.client_ip,
               config_.client_port);
  spdlog::info("Update listener on {}:{}", config_.update_ip,
               config_.update_port);

  return true;
}

void LoadBalancer::stop() {
  if (!running_) {
    return;
  }

  running_ = false;

  ev_io_stop(loop_, &tcp_client_watcher_);
  ev_io_stop(loop_, &udp_update_watcher_);
  ev_timer_stop(loop_, &health_check_timer_);

  // Cleanup connection pool
  connection_pool_->cleanup();

  spdlog::info("Load balancer stopped");
}

bool LoadBalancer::isRunning() const { return running_; }

void LoadBalancer::reloadConfig(const LoadBalancerConfig &config) {
  std::lock_guard<std::mutex> lock(config_mutex_);
  config_ = config;
  server_manager_->updateConfig(config);
}

LoadBalancerConfig LoadBalancer::getConfig() const {
  std::lock_guard<std::mutex> lock(config_mutex_);
  return config_;
}

size_t LoadBalancer::getTotalRequests() const { return total_requests_; }

size_t LoadBalancer::getActiveConnections() const {
  return active_connections_;
}

double LoadBalancer::getAverageResponseTime() const {
  // Placeholder - implement actual response time tracking
  return 0.0;
}

bool LoadBalancer::initializeSockets() {
  // Initialize TCP client socket
  if (!bindTcpSocket(tcp_client_socket_, config_.client_ip,
                     config_.client_port)) {
    return false;
  }

  // Initialize UDP update socket
  if (!bindUdpSocket(udp_update_socket_, config_.update_ip,
                     config_.update_port)) {
    close(tcp_client_socket_);
    tcp_client_socket_ = -1;
    return false;
  }

  return true;
}

void LoadBalancer::closeSockets() {
  if (tcp_client_socket_ >= 0) {
    close(tcp_client_socket_);
    tcp_client_socket_ = -1;
  }

  if (udp_update_socket_ >= 0) {
    close(udp_update_socket_);
    udp_update_socket_ = -1;
  }
}

bool LoadBalancer::bindTcpSocket(int &socket_fd, const std::string &ip,
                                 int port) {
  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    std::cerr << "Failed to create TCP socket: " << strerror(errno)
              << std::endl;
    return false;
  }

  // Set socket options
  int opt = 1;
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    std::cerr << "Failed to set SO_REUSEADDR: " << strerror(errno) << std::endl;
    close(socket_fd);
    return false;
  }

  // Set non-blocking
  int flags = fcntl(socket_fd, F_GETFL, 0);
  if (flags < 0 || fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    std::cerr << "Failed to set non-blocking: " << strerror(errno) << std::endl;
    close(socket_fd);
    return false;
  }

  // Bind socket
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));

  if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
    std::cerr << "Invalid IP address: " << ip << std::endl;
    close(socket_fd);
    return false;
  }

  if (bind(socket_fd, reinterpret_cast<struct sockaddr *>(&addr),
           sizeof(addr)) < 0) {
    std::cerr << "Failed to bind TCP socket: " << strerror(errno) << std::endl;
    close(socket_fd);
    return false;
  }

  // Listen for connections
  if (listen(socket_fd, config_.max_connections) < 0) {
    std::cerr << "Failed to listen: " << strerror(errno) << std::endl;
    close(socket_fd);
    return false;
  }

  return true;
}

bool LoadBalancer::bindUdpSocket(int &socket_fd, const std::string &ip,
                                 int port) {
  socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    std::cerr << "Failed to create UDP socket: " << strerror(errno)
              << std::endl;
    return false;
  }

  // Set socket options
  int opt = 1;
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    std::cerr << "Failed to set SO_REUSEADDR: " << strerror(errno) << std::endl;
    close(socket_fd);
    return false;
  }

  // Set non-blocking
  int flags = fcntl(socket_fd, F_GETFL, 0);
  if (flags < 0 || fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    std::cerr << "Failed to set non-blocking: " << strerror(errno) << std::endl;
    close(socket_fd);
    return false;
  }

  // Bind socket
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));

  if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
    std::cerr << "Invalid IP address: " << ip << std::endl;
    close(socket_fd);
    return false;
  }

  if (bind(socket_fd, reinterpret_cast<struct sockaddr *>(&addr),
           sizeof(addr)) < 0) {
    std::cerr << "Failed to bind UDP socket: " << strerror(errno) << std::endl;
    close(socket_fd);
    return false;
  }

  return true;
}

void LoadBalancer::onTcpClientConnection(struct ev_loop *loop,
                                         struct ev_io *watcher, int revents) {
  (void)loop;
  (void)revents; // Suppress unused parameter warnings
  LoadBalancer *lb = static_cast<LoadBalancer *>(watcher->data);
  spdlog::info("TCP client connection request on listening socket {}",
               watcher->fd);
  lb->acceptTcpConnection(watcher->fd);
}

void LoadBalancer::onUdpUpdateConnection(struct ev_loop *loop,
                                         struct ev_io *watcher, int revents) {
  (void)loop;
  (void)revents; // Suppress unused parameter warnings
  LoadBalancer *lb = static_cast<LoadBalancer *>(watcher->data);
  lb->handleUdpUpdateData(watcher->fd);
}

void LoadBalancer::onHealthCheck(struct ev_loop *loop, struct ev_timer *timer,
                                 int revents) {
  (void)loop;
  (void)revents; // Suppress unused parameter warnings
  LoadBalancer *lb = static_cast<LoadBalancer *>(timer->data);
  lb->server_manager_->performHealthCheck();
  lb->connection_pool_->healthCheck();
}

void LoadBalancer::acceptTcpConnection(int listening_fd) {
  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);

  int client_fd =
      accept(listening_fd, reinterpret_cast<struct sockaddr *>(&client_addr),
             &addr_len);
  if (client_fd < 0) {
    spdlog::error("Failed to accept connection: {}", strerror(errno));
    return;
  }

  // Convert client address to string for logging
  char client_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
  std::string client_addr_str = std::string(client_ip) + ":" +
                                std::to_string(ntohs(client_addr.sin_port));

  spdlog::info("Accepted TCP connection from {} on fd {}", client_addr_str,
               client_fd);
  active_connections_++;

  // Handle the client data immediately
  handleTcpClientData(client_fd);
}

void LoadBalancer::handleTcpClientData(int client_fd) {
  spdlog::info("Handling TCP client data from fd {}", client_fd);
  std::vector<char> buffer(static_cast<size_t>(config_.buffer_size));
  ssize_t bytes_read = recv(client_fd, buffer.data(), buffer.size() - 1, 0);

  if (bytes_read <= 0) {
    if (bytes_read < 0) {
      spdlog::error("Error reading from client: {}", strerror(errno));
    }
    close(client_fd);
    active_connections_--;
    return;
  }

  buffer[static_cast<size_t>(bytes_read)] = '\0';

  // Parse HTTP request
  HttpRequest request = HttpHandler::parseRequest(
      std::string(buffer.data(), static_cast<size_t>(bytes_read)));

  // Handle request
  HttpResponse response = http_handler_->handleClientRequest(request);

  // Send response
  std::string response_str = HttpHandler::serializeResponse(response);
  ssize_t bytes_sent =
      send(client_fd, response_str.c_str(), response_str.length(), 0);

  if (bytes_sent < 0) {
    std::cerr << "Error sending response: " << strerror(errno) << std::endl;
  }

  total_requests_++;
  close(client_fd);
  active_connections_--;
}

void LoadBalancer::handleUdpUpdateData(int update_fd) {
  std::vector<char> buffer(static_cast<size_t>(config_.buffer_size));
  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);

  ssize_t bytes_read =
      recvfrom(update_fd, buffer.data(), buffer.size() - 1, 0,
               reinterpret_cast<struct sockaddr *>(&client_addr), &addr_len);

  if (bytes_read <= 0) {
    if (bytes_read < 0) {
      std::cerr << "Error reading UDP update: " << strerror(errno) << std::endl;
    }
    return;
  }

  buffer[static_cast<size_t>(bytes_read)] = '\0';

  // Convert client address to string
  char client_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
  std::string client_addr_str = std::string(client_ip) + ":" +
                                std::to_string(ntohs(client_addr.sin_port));

  // Handle server update
  http_handler_->handleUdpServerUpdate(
      std::string(buffer.data(), static_cast<size_t>(bytes_read)),
      client_addr_str);

  // Send acknowledgment (UDP)
  std::string ack = "{\"status\":\"received\"}\n";
  sendto(update_fd, ack.c_str(), ack.length(), 0,
         reinterpret_cast<struct sockaddr *>(&client_addr), addr_len);
}

} // namespace GranuloTrack
