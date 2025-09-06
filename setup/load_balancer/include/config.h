#pragma once

#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace GranuloTrack {

struct ServerConfig {
  std::string id;
  std::string ip;
  int port;
  double initial_utilization;
  double current_utilization;
  bool active;
  time_t last_update;

  ServerConfig()
      : port(0), initial_utilization(0.0), current_utilization(0.0),
        active(true), last_update(0) {}
};

struct ServerUpdate {
  std::string server_id;
  std::vector<double> utilizations; // Vector of utilization samples
  double average_utilization;       // Average of the samples
  std::string source;               // "htop" or "granulotrack"
  time_t timestamp;

  ServerUpdate() : average_utilization(0.0), timestamp(0) {}
};

struct LoadBalancerConfig {
  // Network settings
  std::string client_ip;
  int client_port;
  std::string update_ip;
  int update_port;

  // Use case configuration
  std::string use_case;         // "htop" or "granulotrack"
  double initial_min_threshold; // Initial min threshold value
  double initial_max_threshold; // Initial max threshold value

  // Algorithm parameters
  double weight_factor;    // Weight for new updates (default: 0.6)
  double update_threshold; // Threshold for updates (default: 10.0)
  double min_factor;       // Factor for min threshold (default: 0.5)
  double max_factor;       // Factor for max threshold (default: 2.0)

  // Server configurations
  std::vector<ServerConfig> servers;

  // Performance settings
  int max_connections;
  int buffer_size;
  int timeout_seconds;
  int connection_pool_size; // Number of connections per server in pool

  // Connection pool settings
  int connection_wait_timeout; // Seconds to wait for available connection
  int socket_timeout;          // Socket timeout for individual connections
  int connection_timeout;      // Connection timeout in pool (seconds)

  // Health check settings
  int health_check_interval;   // Health check timer interval (seconds)
  int server_health_timeout;   // Server health check timeout (seconds)
  int server_health_threshold; // Server health threshold (seconds)

  LoadBalancerConfig()
      : client_port(0), update_port(0), use_case("htop"),
        initial_min_threshold(25.0), initial_max_threshold(75.0),
        weight_factor(0.6), update_threshold(10.0), min_factor(0.5),
        max_factor(2.0), max_connections(10000), buffer_size(8192),
        timeout_seconds(30), connection_pool_size(16),
        connection_wait_timeout(5), socket_timeout(5), connection_timeout(300),
        health_check_interval(30), server_health_timeout(60),
        server_health_threshold(30) {}
};

class ConfigParser {
public:
  static std::unique_ptr<LoadBalancerConfig>
  parseFromFile(const std::string &filename);
  static std::unique_ptr<LoadBalancerConfig>
  parseFromJson(const std::string &json_str);
  static std::unique_ptr<LoadBalancerConfig>
  parseFromJson(const nlohmann::json &j);

private:
  static void validateConfig(const LoadBalancerConfig &config);
};

} // namespace GranuloTrack
