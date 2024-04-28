CC = gcc
#CFLAGS = -fno-stack-protector -Wl,-z,relro -z execstack -Wno-implicit-function-declaration -Wno-builtin-declaration-mismatch -fno-pie -no-pie
CFLAGS = -fno-stack-protector -Wno-implicit-function-declaration -Wno-builtin-declaration-mismatch -I.
LDFLAGS = -Wl,-rpath=.

SRCS = main.c
OBJS = $(SRCS:.c=.o)
TARGET = prequel

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lsqlite3 -L. -static -lm -lseccomp

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
