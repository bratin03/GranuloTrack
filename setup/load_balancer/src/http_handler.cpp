#include "../include/http_handler.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <chrono>
#include <fast_float/fast_float.h>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <random>
#include <simdjson.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace GranuloTrack {

HttpHandler::HttpHandler(std::shared_ptr<ServerManager> server_manager,
                         std::shared_ptr<ConnectionPool> connection_pool)
    : server_manager_(server_manager), connection_pool_(connection_pool) {}

HttpResponse HttpHandler::handleClientRequest(const HttpRequest &request) {
  if (!isNginxCompatible(request)) {
    HttpResponse response;
    response.status_code = 400;
    response.status_text = "Bad Request";
    response.body = "Incompatible request format";
    return response;
  }

  if (request.method == "GET") {
    return handleGet(request);
  } else if (request.method == "POST") {
    return handlePost(request);
  } else if (request.method == "OPTIONS") {
    return handleOptions(request);
  } else {
    HttpResponse response;
    response.status_code = 405;
    response.status_text = "Method Not Allowed";
    response.body = "Method not supported";
    return response;
  }
}

void HttpHandler::handleServerUpdate(std::string_view update_data) {
  try {
    // Parse JSON update data using SIMDjson for ultra-fast parsing
    simdjson::dom::parser parser;
    simdjson::dom::element json_data;
    auto error = parser.parse(std::string(update_data)).get(json_data);
    if (error) {
      spdlog::error("JSON parsing error: {}", simdjson::error_message(error));
      return;
    }

    ServerUpdate update;

    // Parse server_id
    if (json_data["server_id"].is_string()) {
      update.server_id =
          std::string(json_data["server_id"].get_string().value());
    }

    // Parse average_utilization using FastFloat for ultra-fast conversion
    if (json_data["average_utilization"].is_double()) {
      update.average_utilization =
          json_data["average_utilization"].get_double().value();
    } else if (json_data["average_utilization"].is_string()) {
      std::string util_str =
          std::string(json_data["average_utilization"].get_string().value());
      fast_float::from_chars(util_str.data(), util_str.data() + util_str.size(),
                             update.average_utilization);
    }

    // Parse source
    if (json_data["source"].is_string()) {
      update.source = std::string(json_data["source"].get_string().value());
    }

    // Parse timestamp
    if (json_data["timestamp"].is_int64()) {
      update.timestamp =
          static_cast<long>(json_data["timestamp"].get_int64().value());
    }

    // Parse utilizations vector using FastFloat
    if (json_data["utilizations"].is_array()) {
      simdjson::dom::array utilizations =
          json_data["utilizations"].get_array().value();
      for (auto util : utilizations) {
        if (util.is_double()) {
          update.utilizations.push_back(util.get_double().value());
        } else if (util.is_string()) {
          double value;
          std::string util_str = std::string(util.get_string().value());
          if (fast_float::from_chars(util_str.data(),
                                     util_str.data() + util_str.size(), value)
                  .ec == std::errc{}) {
            update.utilizations.push_back(value);
          }
        }
      }
    }

    if (update.source == "htop") {
      handleHtopUpdate(update);
    } else if (update.source == "granulotrack") {
      handleGranuloTrackUpdate(update);
    }

  } catch (const std::exception &e) {
    spdlog::error("Error parsing server update: {}", e.what());
  }
}

HttpRequest HttpHandler::parseRequest(const std::string &raw_request) {
  HttpRequest request;
  std::istringstream iss(raw_request);
  std::string line;

  // Parse request line
  if (std::getline(iss, line)) {
    std::istringstream line_stream(line);
    line_stream >> request.method >> request.path >> request.version;
  }

  // Parse headers
  while (std::getline(iss, line) && line != "\r" && !line.empty()) {
    size_t colon_pos = line.find(':');
    if (colon_pos != std::string::npos) {
      std::string key = line.substr(0, colon_pos);
      std::string value = line.substr(colon_pos + 1);

      // Remove leading whitespace and \r
      value.erase(0, value.find_first_not_of(" \t\r"));
      if (!value.empty() && value.back() == '\r') {
        value.pop_back();
      }

      request.headers[key] = value;
    }
  }

  // Parse body
  std::stringstream body_stream;
  while (std::getline(iss, line)) {
    body_stream << line << "\n";
  }
  request.body = body_stream.str();

  return request;
}

std::string HttpHandler::serializeResponse(const HttpResponse &response) {
  std::ostringstream oss;

  // Status line
  oss << "HTTP/1.1 " << response.status_code << " " << response.status_text
      << "\r\n";

  // Headers
  for (const auto &header : response.headers) {
    oss << header.first << ": " << header.second << "\r\n";
  }

  // Content-Length if not present
  if (response.headers.find("Content-Length") == response.headers.end()) {
    oss << "Content-Length: " << response.body.length() << "\r\n";
  }

  // End of headers
  oss << "\r\n";

  // Body
  oss << response.body;

  return oss.str();
}

bool HttpHandler::isNginxCompatible(const HttpRequest &request) noexcept {
  // Check if request follows HTTP/1.1 format
  if (request.version != "HTTP/1.1" && request.version != "HTTP/1.0") {
    return false;
  }

  // Check for required headers
  if (request.headers.find("Host") == request.headers.end()) {
    return false;
  }

  return true;
}

HttpResponse
HttpHandler::createNginxCompatibleResponse(const HttpRequest &request) {
  (void)request; // Suppress unused parameter warning
  HttpResponse response;
  response.headers["Server"] = "GranuloTrack-LoadBalancer/1.0";
  response.headers["Date"] = getCurrentTimestamp();
  response.headers["Connection"] = "keep-alive";

  return response;
}

HttpResponse HttpHandler::handleGet(const HttpRequest &request) {
  HttpResponse response = createNginxCompatibleResponse(request);

  if (request.path == "/health") {
    response.status_code = 200;
    response.status_text = "OK";
    response.body = "{\"status\":\"healthy\",\"active_servers\":" +
                    std::to_string(server_manager_->getActiveServerCount()) +
                    "}";
    response.headers["Content-Type"] = "application/json";
  } else if (request.path == "/stats") {
    response.status_code = 200;
    response.status_text = "OK";
    response.body = "{\"average_utilization\":" +
                    std::to_string(server_manager_->getAverageUtilization()) +
                    "}";
    response.headers["Content-Type"] = "application/json";
  } else {
    // Forward request to selected server
    std::string selected_server = server_manager_->getNextServer();
    if (selected_server.empty()) {
      response.status_code = 503;
      response.status_text = "Service Unavailable";
      response.body = "No available servers";
    } else {
      // Forward the request to the selected server
      response = forwardRequestToServer(request, selected_server);
    }
  }

  return response;
}

HttpResponse HttpHandler::handlePost(const HttpRequest &request) {
  HttpResponse response = createNginxCompatibleResponse(request);

  if (request.path == "/update") {
    handleServerUpdate(request.body);
    response.status_code = 200;
    response.status_text = "OK";
    response.body = "{\"status\":\"updated\"}";
    response.headers["Content-Type"] = "application/json";
  } else {
    response.status_code = 404;
    response.status_text = "Not Found";
    response.body = "Endpoint not found";
  }

  return response;
}

HttpResponse HttpHandler::handleOptions(const HttpRequest &request) {
  HttpResponse response = createNginxCompatibleResponse(request);
  response.status_code = 200;
  response.status_text = "OK";
  response.headers["Allow"] = "GET, POST, OPTIONS";
  response.headers["Access-Control-Allow-Origin"] = "*";
  response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
  response.headers["Access-Control-Allow-Headers"] = "Content-Type";

  return response;
}

void HttpHandler::handleHtopUpdate(const ServerUpdate &update) {
  if (isValidServerId(update.server_id)) {
    server_manager_->updateServerUtilization(
        update.server_id, update.utilizations, update.average_utilization);
  }
}

void HttpHandler::handleGranuloTrackUpdate(const ServerUpdate &update) {
  if (isValidServerId(update.server_id)) {
    server_manager_->updateServerUtilization(
        update.server_id, update.utilizations, update.average_utilization);
  }
}

std::string HttpHandler::getCurrentTimestamp() {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);
  auto tm = *std::gmtime(&time_t);

  std::ostringstream oss;
  oss << std::put_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
  return oss.str();
}

std::string HttpHandler::generateRequestId() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<> dis(0, 15);
  static const char *hex_chars = "0123456789abcdef";

  std::string id;
  for (int i = 0; i < 32; ++i) {
    id += hex_chars[dis(gen)];
  }
  return id;
}

bool HttpHandler::isValidServerId(std::string_view server_id) noexcept {
  return !server_id.empty() && server_id.length() <= 64;
}

void HttpHandler::handleTcpClientRequest(int client_fd) {
  std::vector<char> buffer(
      static_cast<size_t>(server_manager_->getConfig().buffer_size));
  ssize_t bytes_read = recv(client_fd, buffer.data(), buffer.size() - 1, 0);

  if (bytes_read <= 0) {
    close(client_fd);
    return;
  }

  buffer[static_cast<size_t>(bytes_read)] = '\0';

  // Parse HTTP request
  HttpRequest request =
      parseRequest(std::string(buffer.data(), static_cast<size_t>(bytes_read)));

  // Handle request
  HttpResponse response = handleClientRequest(request);

  // Send response
  std::string response_str = serializeResponse(response);
  send(client_fd, response_str.c_str(), response_str.length(), 0);

  close(client_fd);
}

void HttpHandler::handleUdpServerUpdate(std::string_view update_data,
                                        std::string_view client_addr) {
  (void)client_addr; // Suppress unused parameter warning

  // Handle the update data
  handleServerUpdate(update_data);
}

HttpResponse HttpHandler::forwardRequestToServer(const HttpRequest &request,
                                                 const std::string &server_id) {
  HttpResponse response;

  // Get server configuration
  const auto &servers = server_manager_->getConfig().servers;
  const auto server_it = std::find_if(
      servers.begin(), servers.end(),
      [&server_id](const ServerConfig &s) { return s.id == server_id; });

  if (server_it == servers.end()) {
    response.status_code = 500;
    response.status_text = "Internal Server Error";
    response.body = "Server configuration not found";
    return response;
  }

  // Get connection from pool
  auto connection = connection_pool_->getConnection(server_id);
  if (!connection) {
    response.status_code = 502;
    response.status_text = "Bad Gateway";
    response.body = "Failed to get connection to backend server";
    return response;
  }

  // Set socket timeout
  struct timeval timeout;
  timeout.tv_sec = server_manager_->getConfig().socket_timeout;
  timeout.tv_usec = 0;
  setsockopt(connection->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
             sizeof(timeout));
  setsockopt(connection->socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
             sizeof(timeout));

  // Forward the original request to backend server
  std::string forwarded_request = serializeRequest(request);
  if (send(connection->socket_fd, forwarded_request.c_str(),
           forwarded_request.length(), 0) < 0) {
    // Connection failed, close it and return error
    connection_pool_->closeConnection(connection);
    response.status_code = 502;
    response.status_text = "Bad Gateway";
    response.body = "Failed to send request to backend server";
    return response;
  }

  // Receive response from backend server
  std::vector<char> buffer(
      static_cast<size_t>(server_manager_->getConfig().buffer_size));
  ssize_t bytes_read =
      recv(connection->socket_fd, buffer.data(), buffer.size() - 1, 0);

  if (bytes_read <= 0) {
    // Connection failed, close it and return error
    connection_pool_->closeConnection(connection);
    response.status_code = 502;
    response.status_text = "Bad Gateway";
    response.body = "No response from backend server";
    return response;
  }

  buffer[static_cast<size_t>(bytes_read)] = '\0';

  // Parse backend response
  response = parseResponse(
      std::string(buffer.data(), static_cast<size_t>(bytes_read)));
  response.headers["X-Server"] = server_id;

  // Return connection to pool for reuse
  connection_pool_->returnConnection(connection);

  return response;
}

std::string HttpHandler::serializeRequest(const HttpRequest &request) {
  std::ostringstream oss;
  oss << request.method << " " << request.path << " " << request.version
      << "\r\n";

  for (const auto &header : request.headers) {
    oss << header.first << ": " << header.second << "\r\n";
  }

  oss << "\r\n";
  if (!request.body.empty()) {
    oss << request.body;
  }

  return oss.str();
}

HttpResponse HttpHandler::parseResponse(const std::string &raw_response) {
  HttpResponse response;
  std::istringstream iss(raw_response);
  std::string line;

  // Parse status line
  if (std::getline(iss, line)) {
    std::istringstream status_stream(line);
    std::string version, status_text;
    status_stream >> version >> response.status_code >> status_text;
    response.status_text = status_text;
  }

  // Parse headers
  while (std::getline(iss, line) && line != "\r" && !line.empty()) {
    size_t colon_pos = line.find(':');
    if (colon_pos != std::string::npos) {
      std::string key = line.substr(0, colon_pos);
      std::string value = line.substr(colon_pos + 1);

      // Remove leading whitespace and \r
      value.erase(0, value.find_first_not_of(" \r"));
      response.headers[key] = value;
    }
  }

  // Parse body
  std::string body;
  while (std::getline(iss, line)) {
    body += line + "\n";
  }
  response.body = body;

  return response;
}

} // namespace GranuloTrack
