CC = /usr/bin/gcc
AS = /usr/bin/as
LD = /usr/bin/ld
CFlags =   -Wall -Wextra -pedantic -std=c99
readpe: peloader.c 
	$(CC) peloader.c -o peloader $(CFlags)

all: readpe