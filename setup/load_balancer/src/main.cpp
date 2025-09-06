#include "../include/load_balancer.h"
#include <ctime>
#include <filesystem>
#include <iostream>
#include <memory>
#include <signal.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace GranuloTrack;

std::unique_ptr<LoadBalancer> g_load_balancer;

void signal_handler(int signal) {
  if (g_load_balancer) {
    spdlog::info("Received signal {}, shutting down...", signal);
    g_load_balancer->stop();
  }
  exit(0);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
    std::cerr << "Example: " << argv[0] << " config.json" << std::endl;
    return 1;
  }

  try {
    // Create logs directory if it doesn't exist
    struct stat st;
    if (stat("logs", &st) == -1) {
      mkdir("logs", 0755);
    }

    // Create timestamped log file
    auto timestamp = std::to_string(std::time(nullptr));
    std::string log_filename = "logs/load_balancer_" + timestamp + ".log";

    // Create basic file logger with immediate flushing
    auto file_logger = spdlog::basic_logger_mt("load_balancer", log_filename);

    // Flush on every log (immediate, but slower)
    file_logger->flush_on(spdlog::level::trace);

    // Update symlink 'logs/latest.log' to point to this run
    std::filesystem::path latest = "logs/latest.log";
    if (std::filesystem::exists(latest))
      std::filesystem::remove(latest);
    std::filesystem::create_symlink(
        std::filesystem::path(log_filename).filename(), latest);

    spdlog::set_default_logger(file_logger);
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");

    spdlog::info("Starting GranuloTrack Load Balancer...");

    // Parse configuration
    auto config = ConfigParser::parseFromFile(argv[1]);
    spdlog::info("Configuration loaded successfully");

    // Create load balancer
    spdlog::info("Creating load balancer instance...");
    g_load_balancer = std::make_unique<LoadBalancer>(*config);

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Start load balancer
    spdlog::info("Starting load balancer...");
    if (!g_load_balancer->start()) {
      spdlog::error("Failed to start load balancer");
      return 1;
    }

    spdlog::info("Load balancer is running. Press Ctrl+C to stop.");

    // Run event loop
    spdlog::info("Starting event loop...");
    ev_run(g_load_balancer->getEventLoop(), 0); // Run the libev event loop

  } catch (const std::exception &e) {
    spdlog::error("Error: {}", e.what());
    return 1;
  }

  return 0;
}
