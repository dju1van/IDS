CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g
LDFLAGS = -lpcap

SRC = src/main.c src/capture.c src/decoder.c src/session.c src/rules.c src/logger.c
OBJ = $(SRC:.c=.o)
TARGET = IDS

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET)