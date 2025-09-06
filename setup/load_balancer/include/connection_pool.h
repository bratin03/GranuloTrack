#pragma once

#include "config.h"
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <unordered_map>

namespace GranuloTrack {

struct Connection {
  int socket_fd;
  std::string server_id;
  time_t last_used;
  bool in_use;

  Connection(int fd, const std::string &id)
      : socket_fd(fd), server_id(id), last_used(time(nullptr)), in_use(false) {}

  ~Connection() {
    if (socket_fd >= 0) {
      close(socket_fd);
    }
  }
};

class ConnectionPool {
public:
  explicit ConnectionPool(const LoadBalancerConfig &config);
  ~ConnectionPool();

  // Connection management
  std::shared_ptr<Connection> getConnection(const std::string &server_id);
  void returnConnection(std::shared_ptr<Connection> conn);
  void closeConnection(std::shared_ptr<Connection> conn);

  // Pool management
  void initializePool();
  void cleanup();
  void healthCheck();

  // Statistics
  size_t getPoolSize(const std::string &server_id) const;
  size_t getActiveConnections(const std::string &server_id) const;
  size_t getTotalConnections() const;

private:
  LoadBalancerConfig config_;

  // Per-server connection pools
  std::unordered_map<std::string, std::queue<std::shared_ptr<Connection>>>
      pools_;
  std::unordered_map<std::string, std::atomic<size_t>> active_connections_;

  // Thread safety
  mutable std::mutex pool_mutex_;
  std::condition_variable pool_cv_;

  // Configuration
  static constexpr size_t MAX_POOL_SIZE = 100; // Maximum connections per server

  // Helper methods
  std::shared_ptr<Connection> createConnection(const std::string &server_id);
  bool isConnectionHealthy(std::shared_ptr<Connection> conn) const noexcept;
  void removeStaleConnections();
};

} // namespace GranuloTrack
