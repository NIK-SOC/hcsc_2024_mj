CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS =

SRC = main.c
OBJ = $(SRC:.c=.o)
BIN = adams

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	strip $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

strip: $(BIN)
	strip $(BIN)

clean:
	rm -f $(OBJ) $(BIN)
