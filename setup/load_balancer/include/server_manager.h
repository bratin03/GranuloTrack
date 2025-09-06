#pragma once

#include "config.h"
#include <absl/container/flat_hash_map.h>
#include <functional>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <string_view>

// Intel TBB for parallel processing
#ifdef USE_TBB
#include <tbb/concurrent_hash_map.h>
#include <tbb/concurrent_priority_queue.h>
#include <tbb/parallel_for.h>
#include <tbb/parallel_reduce.h>
#include <tbb/parallel_sort.h>
#endif

namespace GranuloTrack {

struct ServerState {
  ServerConfig config;
  double utilization;
  bool in_queue;
  time_t last_health_check;
  time_t last_update;

  ServerState()
      : utilization(0.0), in_queue(true), last_health_check(0), last_update(0) {
  }
  ServerState(const ServerConfig &cfg)
      : config(cfg), utilization(cfg.initial_utilization), in_queue(true),
        last_health_check(0), last_update(0) {}
};

class ServerManager {
public:
  explicit ServerManager(const LoadBalancerConfig &config);
  ~ServerManager() = default;

  // Server selection
  std::string getNextServer();
  std::vector<std::string>
  getNextServers(size_t count); // Batch selection for performance
  void updateServerUtilization(const std::string &server_id,
                               const std::vector<double> &utilizations,
                               double average_utilization);

  // Queue management
  void rebuildQueue();
  void removeFromQueue(const std::string &server_id);
  void addToQueue(const std::string &server_id);

  // Health monitoring
  void performHealthCheck();
  bool isServerHealthy(const std::string &server_id) const;

  // Statistics
  double getAverageUtilization() const;
  size_t getActiveServerCount() const;
  std::vector<std::string> getActiveServers() const;

  // Configuration
  void updateConfig(const LoadBalancerConfig &config);
  const LoadBalancerConfig &getConfig() const { return config_; }

private:
  LoadBalancerConfig config_;
  absl::flat_hash_map<std::string, ServerState> servers_;

  // Priority queue for server selection (highest utilization first)
  struct ServerRef {
    std::string id;
    double utilization;
    ServerRef(const std::string &s, double u) : id(s), utilization(u) {}
    
    // Comparator for priority queue (higher utilization = higher priority)
    bool operator<(const ServerRef& other) const {
      return utilization < other.utilization; // Max heap: higher utilization first
    }
  };

#ifdef USE_TBB
  // Lock-free concurrent priority queue ordered by utilization (highest first)
  tbb::concurrent_priority_queue<ServerRef> server_priority_queue_;
#else
  // Fallback: standard priority queue with locks
  std::priority_queue<ServerRef> server_priority_queue_;
#endif

  mutable std::shared_mutex rw_mutex_;

  // Thresholds
  double min_threshold_;
  double max_threshold_;

  // Performance optimizations
  mutable double cached_avg_utilization_{-1.0}; // Cache average utilization
  mutable time_t last_avg_calculation_{0};      // Timestamp of last calculation
  static constexpr time_t AVG_CACHE_DURATION = 5; // Cache for 5 seconds

  // Pre-allocated vectors to avoid allocations
  mutable std::vector<double> temp_utilizations_;
  mutable std::vector<std::string> temp_server_ids_;

  // Helper methods
  void calculateThresholds();
  bool shouldUpdateUtilization(double current, double new_value) const noexcept;
  void updateServerState(const std::string &server_id, double new_utilization);
  bool isServerInRange(const std::string &server_id) const;

  // Priority queue comparator (higher utilization = higher priority)
  bool compareServers(const std::string &a, const std::string &b) const;
};

} // namespace GranuloTrack
