CXX = g++
CXXFLAGS = -O0 -Wall -Wextra -std=c++11 -pthread

TARGET = redis_client
SOURCE = client.cpp

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
