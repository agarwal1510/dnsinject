CC=gcc
CFLAGS=-O3

all:
	$(CC) $(CFLAGS) -g hw4.c -o dnsinject -lpcap -lresolv

clean:
	$(RM) dnsinject