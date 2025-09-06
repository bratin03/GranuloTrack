#include <atomic>
#include <chrono>
#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mysql_connection.h>
#include <mysql_driver.h>
#include <random>
#include <string>
#include <thread>
#include <vector>

class MySQLClient {
private:
  std::string host;
  std::string user;
  std::string password;
  std::string database;
  std::atomic<int> requests{0};
  std::atomic<int> errors{0};

public:
  MySQLClient(const std::string &h = "localhost",
              const std::string &u = "testuser",
              const std::string &p = "testpass",
              const std::string &db = "testdb")
      : host(h), user(u), password(p), database(db) {}

  sql::Connection *getConnection() {
    try {
      sql::mysql::MySQL_Driver *driver;
      driver = sql::mysql::get_mysql_driver_instance();

      std::string url = "tcp://" + host + ":30000";
      sql::Connection *conn = driver->connect(url, user, password);
      conn->setSchema(database);
      return conn;
    } catch (sql::SQLException &e) {
      return nullptr;
    }
  }

  std::string generateRandomString(int min_length, int max_length) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> len_dist(min_length, max_length);
    static std::uniform_int_distribution<> char_dist(32,
                                                     126); // printable ASCII

    int length = len_dist(gen);
    std::string result;
    result.reserve(length);

    for (int i = 0; i < length; ++i) {
      result += static_cast<char>(char_dist(gen));
    }

    return result;
  }

  void createTestTable() {
    sql::Connection *conn = getConnection();
    if (!conn) {
      std::cerr << "Failed to connect to MySQL" << std::endl;
      return;
    }

    try {
      sql::Statement *stmt = conn->createStatement();
      const char *query = "CREATE TABLE IF NOT EXISTS key_value_table ("
                          "id INT AUTO_INCREMENT PRIMARY KEY,"
                          "key_data VARCHAR(1024),"
                          "value_data TEXT,"
                          "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)";
      stmt->execute(query);
      delete stmt;
    } catch (sql::SQLException &e) {
      std::cerr << "Failed to create table: " << e.what() << std::endl;
    }

    delete conn;
  }

  bool insertRecord() {
    sql::Connection *conn = getConnection();
    if (!conn) {
      errors++;
      return false;
    }

    try {
      std::string key = generateRandomString(512, 1024);
      std::string value = generateRandomString(1024, 4096);

      sql::PreparedStatement *pstmt = conn->prepareStatement(
          "INSERT INTO key_value_table (key_data, value_data) VALUES (?, ?)");
      pstmt->setString(1, key);
      pstmt->setString(2, value);
      pstmt->execute();
      delete pstmt;
      requests++;
      delete conn;
      return true;
    } catch (sql::SQLException &e) {
      errors++;
      delete conn;
      return false;
    }
  }

  bool selectRecords() {
    sql::Connection *conn = getConnection();
    if (!conn) {
      errors++;
      return false;
    }

    try {
      sql::Statement *stmt = conn->createStatement();
      sql::ResultSet *res = stmt->executeQuery(
          "SELECT * FROM key_value_table ORDER BY id DESC LIMIT 10");
      delete res;
      delete stmt;
      requests++;
      delete conn;
      return true;
    } catch (sql::SQLException &e) {
      errors++;
      delete conn;
      return false;
    }
  }

  void worker(int num_requests) {
    for (int i = 0; i < num_requests; ++i) {
      if (insertRecord()) {
        selectRecords();
      }
    }
  }

  int getRequests() const { return requests.load(); }
  int getErrors() const { return errors.load(); }
};

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cout << "Usage: " << argv[0] << " <num_clients> <requests_per_client>"
              << std::endl;
    return 1;
  }

  int num_clients = std::atoi(argv[1]);
  int requests_per_client = std::atoi(argv[2]);

  MySQLClient client;
  client.createTestTable();

  std::cout << "Starting " << num_clients << " clients, each sending "
            << requests_per_client << " requests..." << std::endl;

  auto start_time = std::chrono::steady_clock::now();

  std::vector<std::thread> threads;
  for (int i = 0; i < num_clients; ++i) {
    threads.emplace_back(&MySQLClient::worker, &client, requests_per_client);
  }

  for (auto &thread : threads) {
    thread.join();
  }

  auto end_time = std::chrono::steady_clock::now();
  auto total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
      end_time - start_time);

  std::cout << "Test completed in " << std::fixed << std::setprecision(20)
            << total_time.count() / 1000000000.0 << " seconds" << std::endl;
  std::cout << "Total requests: " << client.getRequests() << std::endl;
  std::cout << "Total errors: " << client.getErrors() << std::endl;
  std::cout << "Requests per second: " << std::fixed << std::setprecision(20)
            << (client.getRequests() * 1000000000.0 / total_time.count())
            << std::endl;

  return 0;
}
