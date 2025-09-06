#include "../include/config.h"
#include <arpa/inet.h>
#include <cstring>
#include <fast_float/fast_float.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <simdjson.h>
#include <sstream>
#include <sys/socket.h>

namespace GranuloTrack {

std::unique_ptr<LoadBalancerConfig>
ConfigParser::parseFromFile(const std::string &filename) {
  std::ifstream file(filename);
  if (!file.is_open()) {
    throw std::runtime_error("Cannot open config file: " + filename);
  }

  std::string json_str((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
  return parseFromJson(json_str);
}

std::unique_ptr<LoadBalancerConfig>
ConfigParser::parseFromJson(const std::string &json_str) {
  auto config = std::make_unique<LoadBalancerConfig>();

  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  auto error = parser.parse(json_str).get(doc);
  if (error) {
    throw std::runtime_error("Failed to parse JSON: " +
                             std::string(simdjson::error_message(error)));
  }

  // Parse network settings
  config->client_ip = std::string(doc["client_ip"].get_string().value());
  config->client_port =
      static_cast<int>(doc["client_port"].get_int64().value());
  config->update_ip = std::string(doc["update_ip"].get_string().value());
  config->update_port =
      static_cast<int>(doc["update_port"].get_int64().value());

  // Parse use case configuration with defaults
  if (doc["use_case"].is_string()) {
    config->use_case = std::string(doc["use_case"].get_string().value());
  } else {
    config->use_case = "htop";
  }

  if (doc["initial_min_threshold"].is_double()) {
    config->initial_min_threshold =
        doc["initial_min_threshold"].get_double().value();
  } else {
    config->initial_min_threshold = 25.0;
  }

  if (doc["initial_max_threshold"].is_double()) {
    config->initial_max_threshold =
        doc["initial_max_threshold"].get_double().value();
  } else {
    config->initial_max_threshold = 75.0;
  }

  // Parse algorithm parameters
  config->weight_factor = doc["weight_factor"].get_double().value();
  config->update_threshold = doc["update_threshold"].get_double().value();
  config->min_factor = doc["min_factor"].get_double().value();
  config->max_factor = doc["max_factor"].get_double().value();

  // Parse performance settings
  config->max_connections =
      static_cast<int>(doc["max_connections"].get_int64().value());
  config->buffer_size =
      static_cast<int>(doc["buffer_size"].get_int64().value());
  config->timeout_seconds =
      static_cast<int>(doc["timeout_seconds"].get_int64().value());

  // Parse connection pool settings with defaults
  if (doc["connection_pool_size"].is_int64()) {
    config->connection_pool_size =
        static_cast<int>(doc["connection_pool_size"].get_int64().value());
  } else {
    config->connection_pool_size = 16;
  }

  if (doc["connection_wait_timeout"].is_int64()) {
    config->connection_wait_timeout =
        static_cast<int>(doc["connection_wait_timeout"].get_int64().value());
  } else {
    config->connection_wait_timeout = 5;
  }

  if (doc["socket_timeout"].is_int64()) {
    config->socket_timeout =
        static_cast<int>(doc["socket_timeout"].get_int64().value());
  } else {
    config->socket_timeout = 5;
  }

  if (doc["connection_timeout"].is_int64()) {
    config->connection_timeout =
        static_cast<int>(doc["connection_timeout"].get_int64().value());
  } else {
    config->connection_timeout = 300;
  }

  // Parse health check settings with defaults
  if (doc["health_check_interval"].is_int64()) {
    config->health_check_interval =
        static_cast<int>(doc["health_check_interval"].get_int64().value());
  } else {
    config->health_check_interval = 30;
  }

  if (doc["server_health_timeout"].is_int64()) {
    config->server_health_timeout =
        static_cast<int>(doc["server_health_timeout"].get_int64().value());
  } else {
    config->server_health_timeout = 60;
  }

  if (doc["server_health_threshold"].is_int64()) {
    config->server_health_threshold =
        static_cast<int>(doc["server_health_threshold"].get_int64().value());
  } else {
    config->server_health_threshold = 30;
  }

  // Parse servers
  simdjson::dom::array servers = doc["servers"].get_array().value();
  for (auto server_json : servers) {
    ServerConfig server;
    server.id = std::string(server_json["id"].get_string().value());
    server.ip = std::string(server_json["ip"].get_string().value());
    server.port = static_cast<int>(server_json["port"].get_int64().value());
    server.initial_utilization =
        server_json["initial_utilization"].get_double().value();
    server.current_utilization = server.initial_utilization;
    server.active = true;
    server.last_update = 0;

    config->servers.push_back(server);
  }

  validateConfig(*config);
  return config;
}

void ConfigParser::validateConfig(const LoadBalancerConfig &config) {
  if (config.client_ip.empty()) {
    throw std::runtime_error("Client IP is required");
  }
  if (config.client_port <= 0 || config.client_port > 65535) {
    throw std::runtime_error("Invalid client port: " +
                             std::to_string(config.client_port));
  }
  if (config.update_ip.empty()) {
    throw std::runtime_error("Update IP is required");
  }
  if (config.update_port <= 0 || config.update_port > 65535) {
    throw std::runtime_error("Invalid update port: " +
                             std::to_string(config.update_port));
  }
  if (config.servers.empty()) {
    throw std::runtime_error("At least one server is required");
  }
  if (config.weight_factor < 0.0 || config.weight_factor > 1.0) {
    throw std::runtime_error("Weight factor must be between 0.0 and 1.0");
  }
  if (config.update_threshold < 0.0) {
    throw std::runtime_error("Update threshold must be non-negative");
  }
  if (config.min_factor <= 0.0) {
    throw std::runtime_error("Min factor must be positive");
  }
  if (config.max_factor <= 0.0) {
    throw std::runtime_error("Max factor must be positive");
  }

  // Validate server configurations
  for (const auto &server : config.servers) {
    if (server.id.empty()) {
      throw std::runtime_error("Server ID is required");
    }
    if (server.ip.empty()) {
      throw std::runtime_error("Server IP is required for server: " +
                               server.id);
    }
    if (server.port <= 0 || server.port > 65535) {
      throw std::runtime_error("Invalid server port for server: " + server.id);
    }
    if (server.initial_utilization < 0.0) {
      throw std::runtime_error(
          "Initial utilization must be non-negative for server: " + server.id);
    }
  }
}

} // namespace GranuloTrack
