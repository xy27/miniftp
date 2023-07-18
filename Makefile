.PHONY:clean all

CC=gcc
CFLAGS=-Wall -g
BIN=miniftpd
OBJECTS=main.o session.o ftpproto.o privparent.o \
		sysutil.o str.o tunable.o parseconf.o \
		privsock.o hash.o
LIBS=-lcrypt

all:$(BIN)

$(BIN):$(OBJECTS)
		 $(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(BIN)

