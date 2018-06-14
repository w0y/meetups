CC=gcc
CFLAGS=-std=c99 -pedantic -Wall -D_XOPEN_SOURCE=500\
-D_DEFAULT_SOURCE

SRV_NAME=service

all: $(SRV_NAME)

$(SRV_NAME): main.o
	$(CC) $(LFLAGS) -o $(SRV_NAME) $<

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o $(SRV_NAME)

.PHONY: all clean
