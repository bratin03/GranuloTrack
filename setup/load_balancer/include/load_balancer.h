#pragma once

#include "config.h"
#include "connection_pool.h"
#include "http_handler.h"
#include "server_manager.h"
#include <atomic>
#include <ev.h>
#include <glog/logging.h>
#include <memory>
#include <thread>

namespace GranuloTrack {

class LoadBalancer {
public:
  explicit LoadBalancer(const LoadBalancerConfig &config);
  ~LoadBalancer();

  // Lifecycle
  bool start();
  void stop();
  bool isRunning() const;

  // Configuration
  void reloadConfig(const LoadBalancerConfig &config);
  LoadBalancerConfig getConfig() const;

  // Statistics
  size_t getTotalRequests() const;
  size_t getActiveConnections() const;
  double getAverageResponseTime() const;

  // Event loop access
  struct ev_loop *getEventLoop() const { return loop_; }

private:
  LoadBalancerConfig config_;
  std::shared_ptr<ServerManager> server_manager_;
  std::shared_ptr<ConnectionPool> connection_pool_;
  std::shared_ptr<HttpHandler> http_handler_;

  // Event loop
  struct ev_loop *loop_;
  struct ev_io tcp_client_watcher_;
  struct ev_io udp_update_watcher_;
  struct ev_timer health_check_timer_;

  // State
  std::atomic<bool> running_;
  std::atomic<size_t> total_requests_;
  std::atomic<size_t> active_connections_;

  // File descriptors
  int tcp_client_socket_;
  int udp_update_socket_;

  // Event handlers
  static void onTcpClientConnection(struct ev_loop *loop, struct ev_io *watcher,
                                    int revents);
  static void onUdpUpdateConnection(struct ev_loop *loop, struct ev_io *watcher,
                                    int revents);
  static void onHealthCheck(struct ev_loop *loop, struct ev_timer *timer,
                            int revents);

  // Helper methods
  bool initializeSockets();
  void closeSockets();
  bool bindTcpSocket(int &socket_fd, const std::string &ip, int port);
  bool bindUdpSocket(int &socket_fd, const std::string &ip, int port);
  void acceptTcpConnection(int listening_fd);
  void handleTcpClientData(int client_fd);
  void handleUdpUpdateData(int update_fd);

  // Thread safety
  mutable std::mutex config_mutex_;
};

} // namespace GranuloTrack
