#pragma once

#include "config.h"
#include "connection_pool.h"
#include "server_manager.h"
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace GranuloTrack {

struct HttpRequest {
  std::string method;
  std::string path;
  std::string version;
  std::unordered_map<std::string, std::string> headers;
  std::string body;
};

struct HttpResponse {
  int status_code;
  std::string status_text;
  std::unordered_map<std::string, std::string> headers;
  std::string body;

  HttpResponse() : status_code(200), status_text("OK") {}
};

// ServerUpdate is now defined in config.h

class HttpHandler {
public:
  explicit HttpHandler(std::shared_ptr<ServerManager> server_manager,
                       std::shared_ptr<ConnectionPool> connection_pool);
  ~HttpHandler() = default;

  // Request handling
  HttpResponse handleClientRequest(const HttpRequest &request);
  void handleServerUpdate(std::string_view update_data);

  // TCP/UDP handling
  void handleTcpClientRequest(int client_fd);
  void handleUdpServerUpdate(std::string_view update_data,
                             std::string_view client_addr);

  // HTTP parsing
  static HttpRequest parseRequest(const std::string &raw_request);
  static std::string serializeResponse(const HttpResponse &response);
  static std::string serializeRequest(const HttpRequest &request);
  static HttpResponse parseResponse(const std::string &raw_response);

  // Nginx compatibility
  static bool isNginxCompatible(const HttpRequest &request) noexcept;
  static HttpResponse createNginxCompatibleResponse(const HttpRequest &request);

private:
  std::shared_ptr<ServerManager> server_manager_;
  std::shared_ptr<ConnectionPool> connection_pool_;

  // Request handlers
  HttpResponse handleGet(const HttpRequest &request);
  HttpResponse handlePost(const HttpRequest &request);
  HttpResponse handleOptions(const HttpRequest &request);

  // Update handlers
  void handleHtopUpdate(const ServerUpdate &update);
  void handleGranuloTrackUpdate(const ServerUpdate &update);

  // Helper methods
  static std::string getCurrentTimestamp();
  static std::string generateRequestId();
  static bool isValidServerId(std::string_view server_id) noexcept;

  // Request forwarding
  HttpResponse forwardRequestToServer(const HttpRequest &request,
                                      const std::string &server_id);
};

} // namespace GranuloTrack
