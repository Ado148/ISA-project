EXECUTABLE = dhcp-stats
CC = g++
CFLAGS = -Wall -Wextra -pedantic
LIBS = -lpcap -lncurses

default: $(EXECUTABLE) clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(EXECUTABLE).o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

dhcp-stats.o: $(EXECUTABLE).cpp
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f *.o