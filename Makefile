CC = gcc
CFLAG = -Wall -Wextra -std=c23 -pedantic -g
LDFLAG = 
SRC = src/slub.c
TARGET = target/libslub.so


slub: $(SRC)
	$(CC) $(CFLAG) -shared -fPIC $< -o $(TARGET) -nostdlib

malloc: $(SRC)
	$(CC) $(CFLAG) -D REPLACE_MALLOC -shared -fPIC $< -o $(TARGET) -nostdlib
