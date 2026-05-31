CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lssl -lcrypto

TARGET = htdes
SRCS = htdes.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean