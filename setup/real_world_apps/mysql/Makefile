CXX = g++
CXXFLAGS = -O0 -Wall -Wextra -std=c++11 -pthread
LDFLAGS = -lmysqlcppconn

TARGET = mysql_client
SOURCE = client.cpp

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
