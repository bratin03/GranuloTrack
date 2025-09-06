#include "../include/server_manager.h"
#include <algorithm>
#include <chrono>
#include <numeric>
#include <spdlog/spdlog.h>

// Intel TBB for parallel processing
#ifdef USE_TBB
#include <tbb/blocked_range.h>
#include <tbb/parallel_for.h>
#include <tbb/parallel_reduce.h>
#endif

namespace GranuloTrack {

ServerManager::ServerManager(const LoadBalancerConfig &config)
    : config_(config) {

  // Initialize thresholds based on use case
  if (config_.use_case == "htop") {
    // Htop: utilization 0-100, use initial thresholds from config
    min_threshold_ = config_.initial_min_threshold;
    max_threshold_ = config_.initial_max_threshold;
  } else if (config_.use_case == "granulotrack") {
    // GranuloTrack: CPU burst of any length, use configurable range
    min_threshold_ = config_.initial_min_threshold;
    max_threshold_ = config_.initial_max_threshold;
  } else {
    // Default fallback
    min_threshold_ = config_.initial_min_threshold;
    max_threshold_ = config_.initial_max_threshold;
  }

  // Pre-allocate vectors for performance
  temp_utilizations_.reserve(config.servers.size());
  temp_server_ids_.reserve(config.servers.size());

  // Initialize servers
  for (const auto &server_config : config.servers) {
    servers_[server_config.id] = ServerState(server_config);

    // Add to priority queue
    server_priority_queue_.emplace(server_config.id, server_config.initial_utilization);
  }

  // Calculate initial thresholds based on server utilizations
  calculateThresholds();

  spdlog::info("ServerManager initialized with {} servers for use case: {}",
               config.servers.size(), config_.use_case);
  spdlog::info("Initial thresholds: min={}, max={}", min_threshold_,
               max_threshold_);
}

std::string ServerManager::getNextServer() {
#ifdef USE_TBB
  // Lock-free approach with TBB concurrent priority queue
  std::vector<ServerRef> checked_servers; // To put back servers not in range
  
  // Check servers from highest utilization down (lock-free)
  ServerRef server_ref("", 0.0);
  while (server_priority_queue_.try_pop(server_ref)) {
    // Check if server is active and in range
    std::shared_lock<std::shared_mutex> lock(rw_mutex_);
    auto it = servers_.find(server_ref.id);
    if (it != servers_.end() && 
        it->second.config.active && 
        server_ref.utilization >= min_threshold_ && 
        server_ref.utilization <= max_threshold_) {
      
      spdlog::info("Selected server: {} (utilization: {})", server_ref.id, server_ref.utilization);
      return server_ref.id;
    }
    lock.unlock(); // Release lock quickly
    
    // Keep track of servers we've checked for fallback
    checked_servers.push_back(server_ref);
  }

  // Fallback: return highest utilization server regardless of range
  if (!checked_servers.empty()) {
    // checked_servers is already sorted by utilization (highest first)
    const ServerRef& best_server = checked_servers[0];
    std::shared_lock<std::shared_mutex> lock(rw_mutex_);
    auto it = servers_.find(best_server.id);
    
    if (it != servers_.end() && it->second.config.active) {
      spdlog::warn("No servers in range, falling back to highest utilization server");
      spdlog::info("Fallback selected server: {} (utilization: {})", best_server.id, best_server.utilization);
      return best_server.id;
    }
  }
#else
  // Fallback: standard priority queue with locks
  std::shared_lock<std::shared_mutex> lock(rw_mutex_);

  // Create a temporary priority queue to check servers in order
  std::priority_queue<ServerRef> temp_queue = server_priority_queue_;
  std::vector<ServerRef> checked_servers; // To put back servers not in range

  // Check servers from highest utilization down
  while (!temp_queue.empty()) {
    ServerRef server_ref = temp_queue.top();
    temp_queue.pop();

    // Check if server is active and in range
    auto it = servers_.find(server_ref.id);
    if (it != servers_.end() && 
        it->second.config.active && 
        server_ref.utilization >= min_threshold_ && 
        server_ref.utilization <= max_threshold_) {
      
      spdlog::info("Selected server: {} (utilization: {})", server_ref.id, server_ref.utilization);
      return server_ref.id;
    }

    // Keep track of servers we've checked for fallback
    checked_servers.push_back(server_ref);
  }

  // Fallback: return highest utilization server regardless of range
  if (!checked_servers.empty()) {
    // checked_servers is already sorted by utilization (highest first)
    const ServerRef& best_server = checked_servers[0];
    auto it = servers_.find(best_server.id);
    
    if (it != servers_.end() && it->second.config.active) {
      spdlog::warn("No servers in range, falling back to highest utilization server");
      spdlog::info("Fallback selected server: {} (utilization: {})", best_server.id, best_server.utilization);
      return best_server.id;
    }
  }
#endif

  spdlog::warn("No servers available");
  return "";
}

std::vector<std::string> ServerManager::getNextServers(size_t count) {
  std::vector<std::string> selected_servers;
  selected_servers.reserve(count);

#ifdef USE_TBB
  // Lock-free approach with TBB concurrent priority queue
  std::vector<ServerRef> checked_servers; // To put back servers not in range
  
  // Select top N servers in range (lock-free)
  ServerRef server_ref("", 0.0);
  while (server_priority_queue_.try_pop(server_ref) && selected_servers.size() < count) {
    // Check if server is active and in range
    std::shared_lock<std::shared_mutex> lock(rw_mutex_);
    auto it = servers_.find(server_ref.id);
    if (it != servers_.end() && 
        it->second.config.active && 
        server_ref.utilization >= min_threshold_ && 
        server_ref.utilization <= max_threshold_) {
      
      selected_servers.push_back(server_ref.id);
    }
    lock.unlock(); // Release lock quickly
    
    // Keep track of servers we've checked
    checked_servers.push_back(server_ref);
  }
#else
  // Fallback: standard priority queue with locks
  std::shared_lock<std::shared_mutex> lock(rw_mutex_);

  // Create a temporary priority queue to check servers in order
  std::priority_queue<ServerRef> temp_queue = server_priority_queue_;

  // Select top N servers in range
  while (!temp_queue.empty() && selected_servers.size() < count) {
    ServerRef server_ref = temp_queue.top();
    temp_queue.pop();

    // Check if server is active and in range
    auto it = servers_.find(server_ref.id);
    if (it != servers_.end() && 
        it->second.config.active && 
        server_ref.utilization >= min_threshold_ && 
        server_ref.utilization <= max_threshold_) {
      
      selected_servers.push_back(server_ref.id);
    }
  }
#endif

  if (selected_servers.empty()) {
    spdlog::warn("No servers in range for batch selection");
  } else {
    std::shared_lock<std::shared_mutex> lock(rw_mutex_);
    spdlog::info("Batch selected {} servers out of {} requested (highest utilization: {})",
                 selected_servers.size(), count, 
                 !selected_servers.empty() ? servers_.find(selected_servers[0])->second.utilization : 0.0);
  }

  return selected_servers;
}

void ServerManager::updateServerUtilization(
    const std::string &server_id, const std::vector<double> &utilizations,
    double average_utilization) {
  std::shared_lock<std::shared_mutex> lock(rw_mutex_);

  const auto it = servers_.find(server_id);
  if (it == servers_.end()) {
    spdlog::warn("Server {} not found for utilization update", server_id);
    return;
  }

  ServerState &server = it->second;
  double current_utilization = server.utilization;

  // Validate utilization is reasonable (basic sanity check)
  if (average_utilization < 0.0 || average_utilization > 10000.0) {
    spdlog::warn("Server {} utilization {} outside reasonable range [0, 10000]",
                 server_id, average_utilization);
    return;
  }

  // Check if average is within threshold
  if (!shouldUpdateUtilization(current_utilization, average_utilization)) {
    spdlog::info("Server {} utilization update skipped (within threshold)",
                 server_id);
    return;
  }

  // Apply weighted average to each sample, then take the overall average
  std::vector<double> weighted_samples;
  for (double sample : utilizations) {
    double weighted_sample =
        (1.0 - config_.weight_factor) * current_utilization +
        config_.weight_factor * sample;
    weighted_samples.push_back(weighted_sample);
  }

  // Calculate final weighted average
  double final_utilization = 0.0;
  if (!weighted_samples.empty()) {
    final_utilization =
        std::accumulate(weighted_samples.begin(), weighted_samples.end(), 0.0) /
        static_cast<double>(weighted_samples.size());
  }

  updateServerState(server_id, final_utilization);

  // Invalidate cache when utilization changes
  cached_avg_utilization_ = -1.0;

  spdlog::info("Server {} utilization updated: {} -> {}", server_id,
               current_utilization, final_utilization);
}

void ServerManager::rebuildQueue() {
  std::unique_lock<std::shared_mutex> lock(rw_mutex_);

#ifdef USE_TBB
  // Clear current TBB concurrent priority queue
  server_priority_queue_ = tbb::concurrent_priority_queue<ServerRef>();

  // Rebuild priority queue with all active servers (ordered by utilization)
  for (const auto &pair : servers_) {
    const std::string &server_id = pair.first;
    const ServerState &server = pair.second;

    if (server.config.active) {
      server_priority_queue_.push(ServerRef(server_id, server.utilization));
    }
  }
#else
  // Clear current standard priority queue
  server_priority_queue_ = std::priority_queue<ServerRef>();

  // Rebuild priority queue with all active servers (ordered by utilization)
  for (const auto &pair : servers_) {
    const std::string &server_id = pair.first;
    const ServerState &server = pair.second;

    if (server.config.active) {
      server_priority_queue_.emplace(server_id, server.utilization);
    }
  }
#endif

  calculateThresholds();
}

void ServerManager::removeFromQueue(const std::string &server_id) {
  std::unique_lock<std::shared_mutex> lock(rw_mutex_);

  auto it = servers_.find(server_id);
  if (it != servers_.end()) {
    it->second.in_queue = false;
  }

  // Rebuild queue to remove the server
  rebuildQueue();
}

void ServerManager::addToQueue(const std::string &server_id) {
  std::unique_lock<std::shared_mutex> lock(rw_mutex_);

  auto it = servers_.find(server_id);
  if (it != servers_.end()) {
    it->second.in_queue = true;
    // Add to priority queue (will be ordered by utilization)
#ifdef USE_TBB
    server_priority_queue_.push(ServerRef(server_id, it->second.utilization));
#else
    server_priority_queue_.emplace(server_id, it->second.utilization);
#endif
  }
}

void ServerManager::performHealthCheck() {
  std::shared_lock<std::shared_mutex> lock(rw_mutex_);

  auto now = std::chrono::system_clock::now();
  auto now_time_t = std::chrono::system_clock::to_time_t(now);

#ifdef USE_TBB
  // Parallel health check using TBB
  std::vector<std::pair<std::string, ServerState *>> server_ptrs;
  server_ptrs.reserve(servers_.size());

  for (auto &pair : servers_) {
    server_ptrs.emplace_back(pair.first, &pair.second);
  }

  tbb::parallel_for(tbb::blocked_range<size_t>(0, server_ptrs.size()),
                    [&](const tbb::blocked_range<size_t> &range) {
                      for (size_t i = range.begin(); i != range.end(); ++i) {
                        ServerState *server = server_ptrs[i].second;
                        // Simple health check - in production, implement actual
                        // health checks
                        if (now_time_t - server->last_health_check >
                            config_.server_health_threshold) {
                          server->last_health_check = now_time_t;
                          // For now, assume server is healthy if we haven't
                          // heard from it recently In production, implement
                          // actual health check logic
                        }
                      }
                    });
#else
  // Sequential health check
  for (auto &pair : servers_) {
    ServerState &server = pair.second;

    // Simple health check - in production, implement actual health checks
    if (now_time_t - server.last_health_check >
        config_.server_health_threshold) {
      server.last_health_check = now_time_t;

      // For now, assume server is healthy if we haven't heard from it recently
      // In production, implement actual health check logic
    }
  }
#endif
}

bool ServerManager::isServerHealthy(const std::string &server_id) const {
  std::shared_lock<std::shared_mutex> lock(rw_mutex_);

  auto it = servers_.find(server_id);
  if (it == servers_.end()) {
    return false;
  }

  const ServerState &server = it->second;
  auto now = std::chrono::system_clock::now();
  auto now_time_t = std::chrono::system_clock::to_time_t(now);

  // Server is healthy if we've heard from it within the configured timeout
  return (now_time_t - server.last_health_check) <
         config_.server_health_timeout;
}

double ServerManager::getAverageUtilization() const {
  std::shared_lock<std::shared_mutex> lock(rw_mutex_);

  if (servers_.empty()) {
    return 0.0;
  }

  // Check cache first
  auto now =
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  if (cached_avg_utilization_ >= 0.0 &&
      (now - last_avg_calculation_) < AVG_CACHE_DURATION) {
    return cached_avg_utilization_;
  }

  // Calculate average (optimized with pre-allocated vector)
  temp_utilizations_.clear();
  temp_utilizations_.reserve(servers_.size());

  for (const auto &pair : servers_) {
    if (pair.second.config.active) {
      temp_utilizations_.push_back(pair.second.utilization);
    }
  }

  if (temp_utilizations_.empty()) {
    cached_avg_utilization_ = 0.0;
  } else {
#ifdef USE_TBB
    // Parallel reduction for large datasets
    if (temp_utilizations_.size() > 100) {
      cached_avg_utilization_ =
          tbb::parallel_reduce(
              tbb::blocked_range<size_t>(0, temp_utilizations_.size()), 0.0,
              [&](const tbb::blocked_range<size_t> &range, double sum) {
                for (size_t i = range.begin(); i != range.end(); ++i) {
                  sum += temp_utilizations_[i];
                }
                return sum;
              },
              std::plus<double>()) /
          static_cast<double>(temp_utilizations_.size());
    } else {
      cached_avg_utilization_ = std::accumulate(temp_utilizations_.begin(),
                                                temp_utilizations_.end(), 0.0) /
                                static_cast<double>(temp_utilizations_.size());
    }
#else
    cached_avg_utilization_ = std::accumulate(temp_utilizations_.begin(),
                                              temp_utilizations_.end(), 0.0) /
                              static_cast<double>(temp_utilizations_.size());
#endif
  }

  last_avg_calculation_ = now;
  return cached_avg_utilization_;
}

size_t ServerManager::getActiveServerCount() const {
  std::shared_lock<std::shared_mutex> lock(rw_mutex_);

#ifdef USE_TBB
  // Parallel count for large datasets
  if (servers_.size() > 50) {
    return static_cast<size_t>(tbb::parallel_reduce(
        tbb::blocked_range<size_t>(0, servers_.size()), 0,
        [&](const tbb::blocked_range<size_t> &range, int count) {
          auto it = servers_.begin();
          std::advance(it, range.begin());
          for (size_t i = range.begin(); i != range.end(); ++i, ++it) {
            if (it->second.config.active) {
              count++;
            }
          }
          return count;
        },
        std::plus<int>()));
  } else {
    return static_cast<size_t>(
        std::count_if(servers_.begin(), servers_.end(), [](const auto &pair) {
          return pair.second.config.active;
        }));
  }
#else
  return static_cast<size_t>(
      std::count_if(servers_.begin(), servers_.end(), [](const auto &pair) {
        return pair.second.config.active;
      }));
#endif
}

std::vector<std::string> ServerManager::getActiveServers() const {
  std::shared_lock<std::shared_mutex> lock(rw_mutex_);

  std::vector<std::string> active_servers;
  for (const auto &pair : servers_) {
    if (pair.second.config.active) {
      active_servers.push_back(pair.first);
    }
  }

  return active_servers;
}

void ServerManager::updateConfig(const LoadBalancerConfig &config) {
  std::unique_lock<std::shared_mutex> lock(rw_mutex_);

  config_ = config;

  // Update existing servers and add new ones
  for (const auto &server_config : config.servers) {
    auto it = servers_.find(server_config.id);
    if (it != servers_.end()) {
      // Update existing server config
      it->second.config = server_config;
    } else {
      // Add new server
      servers_[server_config.id] = ServerState(server_config);
    }
  }

  // Remove servers that are no longer in config
  std::vector<std::string> to_remove;
  for (const auto &pair : servers_) {
    bool found = false;
    for (const auto &server_config : config.servers) {
      if (pair.first == server_config.id) {
        found = true;
        break;
      }
    }
    if (!found) {
      to_remove.push_back(pair.first);
    }
  }

  for (const auto &server_id : to_remove) {
    servers_.erase(server_id);
  }

  rebuildQueue();
}

void ServerManager::calculateThresholds() {
  double avg_utilization = getAverageUtilization();
  min_threshold_ = avg_utilization * config_.min_factor;
  max_threshold_ = avg_utilization * config_.max_factor;
}

bool ServerManager::shouldUpdateUtilization(double current,
                                            double new_value) const noexcept {
  return std::abs(new_value - current) > config_.update_threshold;
}

void ServerManager::updateServerState(const std::string &server_id,
                                      double new_utilization) {
  auto it = servers_.find(server_id);
  if (it == servers_.end()) {
    return;
  }

  ServerState &server = it->second;
  server.utilization = new_utilization;
  server.last_update =
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

  // Add updated server to priority queue (will be ordered by new utilization)
  // Note: This creates duplicates in the queue, but they're handled correctly
  // during selection since we check the actual server state
#ifdef USE_TBB
  server_priority_queue_.push(ServerRef(server_id, new_utilization));
#else
  server_priority_queue_.emplace(server_id, new_utilization);
#endif
}

bool ServerManager::isServerInRange(const std::string &server_id) const {
  auto it = servers_.find(server_id);
  if (it == servers_.end()) {
    return false;
  }

  const ServerState &server = it->second;
  return server.utilization >= min_threshold_ &&
         server.utilization <= max_threshold_;
}

bool ServerManager::compareServers(const std::string &a,
                                   const std::string &b) const {
  auto it_a = servers_.find(a);
  auto it_b = servers_.find(b);

  if (it_a == servers_.end() || it_b == servers_.end()) {
    return false;
  }

  // Higher utilization = higher priority
  return it_a->second.utilization > it_b->second.utilization;
}

// sortQueue method removed - using lock-free queue instead

} // namespace GranuloTrack
