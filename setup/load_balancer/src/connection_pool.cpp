#include "../include/connection_pool.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <unistd.h>

namespace GranuloTrack {

ConnectionPool::ConnectionPool(const LoadBalancerConfig &config)
    : config_(config) {
  // Initialize active connection counters
  for (const auto &server : config_.servers) {
    active_connections_[server.id] = 0;
  }
}

ConnectionPool::~ConnectionPool() { cleanup(); }

void ConnectionPool::initializePool() {
  std::lock_guard<std::mutex> lock(pool_mutex_);

  for (const auto &server : config_.servers) {
    // Pre-create connections for each server based on config
    for (int i = 0; i < config_.connection_pool_size; ++i) {
      auto conn = createConnection(server.id);
      if (conn) {
        pools_[server.id].push(conn);
      }
    }
  }

  spdlog::info("Connection pool initialized with {} connections per server",
               config_.connection_pool_size);
}

std::shared_ptr<Connection>
ConnectionPool::getConnection(const std::string &server_id) {
  std::unique_lock<std::mutex> lock(pool_mutex_);

  // Wait for available connection with timeout
  if (pools_[server_id].empty()) {
    // Try to create a new connection if pool is empty
    auto new_conn = createConnection(server_id);
    if (new_conn) {
      active_connections_[server_id]++;
      new_conn->in_use = true;
      new_conn->last_used = time(nullptr);
      return new_conn;
    }

    // If we can't create a new connection, wait for one to be returned
    if (pool_cv_.wait_for(
            lock, std::chrono::seconds(config_.connection_wait_timeout),
            [this, &server_id] { return !pools_[server_id].empty(); })) {
      auto conn = pools_[server_id].front();
      pools_[server_id].pop();
      active_connections_[server_id]++;
      conn->in_use = true;
      conn->last_used = time(nullptr);
      return conn;
    }

    spdlog::warn("Timeout waiting for connection to server {}", server_id);
    return nullptr;
  }

  auto conn = pools_[server_id].front();
  pools_[server_id].pop();
  active_connections_[server_id]++;
  conn->in_use = true;
  conn->last_used = time(nullptr);

  return conn;
}

void ConnectionPool::returnConnection(std::shared_ptr<Connection> conn) {
  if (!conn)
    return;

  std::lock_guard<std::mutex> lock(pool_mutex_);

  if (isConnectionHealthy(conn)) {
    conn->in_use = false;
    pools_[conn->server_id].push(conn);
    active_connections_[conn->server_id]--;
    pool_cv_.notify_one();
  } else {
    // Connection is unhealthy, close it
    closeConnection(conn);
  }
}

void ConnectionPool::closeConnection(std::shared_ptr<Connection> conn) {
  if (!conn)
    return;

  std::lock_guard<std::mutex> lock(pool_mutex_);

  if (conn->in_use) {
    active_connections_[conn->server_id]--;
  }

  // Connection will be closed in destructor
  conn.reset();
}

std::shared_ptr<Connection>
ConnectionPool::createConnection(const std::string &server_id) {
  // Find server configuration
  const ServerConfig *server_config = nullptr;
  for (const auto &server : config_.servers) {
    if (server.id == server_id) {
      server_config = &server;
      break;
    }
  }

  if (!server_config) {
    spdlog::error("Server configuration not found for {}", server_id);
    return nullptr;
  }

  // Create socket
  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    spdlog::error("Failed to create socket for {}", server_id);
    return nullptr;
  }

  // Set socket options
  int opt = 1;
  setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  // Set timeout
  struct timeval timeout;
  timeout.tv_sec = config_.socket_timeout;
  timeout.tv_usec = 0;
  setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  // Connect to server
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(static_cast<uint16_t>(server_config->port));

  if (inet_pton(AF_INET, server_config->ip.c_str(), &server_addr.sin_addr) <=
      0) {
    spdlog::error("Invalid server address for {}", server_id);
    close(socket_fd);
    return nullptr;
  }

  if (connect(socket_fd, reinterpret_cast<struct sockaddr *>(&server_addr),
              sizeof(server_addr)) < 0) {
    spdlog::error("Failed to connect to {} at {}:{}", server_id,
                  server_config->ip, server_config->port);
    close(socket_fd);
    return nullptr;
  }

  spdlog::info("Created connection to {}", server_id);
  return std::make_shared<Connection>(socket_fd, server_id);
}

bool ConnectionPool::isConnectionHealthy(
    std::shared_ptr<Connection> conn) const noexcept {
  if (!conn || conn->socket_fd < 0) {
    return false;
  }

  // Check if connection is too old
  time_t now = time(nullptr);
  if (now - conn->last_used > config_.connection_timeout) {
    return false;
  }

  // Simple health check - try to send a small amount of data
  int error = 0;
  socklen_t len = sizeof(error);
  int retval = getsockopt(conn->socket_fd, SOL_SOCKET, SO_ERROR, &error, &len);

  return retval == 0 && error == 0;
}

void ConnectionPool::healthCheck() {
  std::lock_guard<std::mutex> lock(pool_mutex_);

  for (auto &[server_id, pool] : pools_) {
    std::queue<std::shared_ptr<Connection>> healthy_connections;

    while (!pool.empty()) {
      auto conn = pool.front();
      pool.pop();

      if (isConnectionHealthy(conn)) {
        healthy_connections.push(conn);
      } else {
        spdlog::info("Removing unhealthy connection to {}", server_id);
        conn.reset();
      }
    }

    pool = std::move(healthy_connections);
  }

  removeStaleConnections();
}

void ConnectionPool::removeStaleConnections() {
  for (auto &[server_id, pool] : pools_) {
    if (pool.size() > MAX_POOL_SIZE) {
      // Remove oldest connections
      size_t to_remove = pool.size() - MAX_POOL_SIZE;
      for (size_t i = 0; i < to_remove; ++i) {
        if (!pool.empty()) {
          pool.pop();
        }
      }
    }
  }
}

void ConnectionPool::cleanup() {
  std::lock_guard<std::mutex> lock(pool_mutex_);

  for (auto &[server_id, pool] : pools_) {
    while (!pool.empty()) {
      pool.pop();
    }
  }

  pools_.clear();
  active_connections_.clear();
}

size_t ConnectionPool::getPoolSize(const std::string &server_id) const {
  std::lock_guard<std::mutex> lock(pool_mutex_);
  const auto it = pools_.find(server_id);
  return (it != pools_.end()) ? it->second.size() : 0;
}

size_t
ConnectionPool::getActiveConnections(const std::string &server_id) const {
  std::lock_guard<std::mutex> lock(pool_mutex_);
  const auto it = active_connections_.find(server_id);
  return (it != active_connections_.end()) ? it->second.load() : 0;
}

size_t ConnectionPool::getTotalConnections() const {
  std::lock_guard<std::mutex> lock(pool_mutex_);
  size_t total = 0;
  for (const auto &[server_id, pool] : pools_) {
    total += pool.size();
  }
  for (const auto &[server_id, count] : active_connections_) {
    total += count.load();
  }
  return total;
}

} // namespace GranuloTrack
