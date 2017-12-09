CC=gcc
CFLAGS=-O3

all: dnsinject

dnsinject: inject.c
	$(CC) $(CFLAGS) -g inject.c -o dnsinject -lpcap -lresolv -lnet

clean:
	$(RM) dnsinject
