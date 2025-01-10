CC = gcc
CFLAG = -Wall -Wextra -std=c23 -pedantic -g
LDFLAG = 
SRC = src/slub.c
TARGET = target/libslub.so


slub: $(SRC)
	$(CC) $(CFLAG) -shared -fPIC $< -o $(TARGET) -nostdlib


test: test/test.c
	$(CC) $(CFLAG) $< -o test/$@ -L. -fopenmp -l:target/libslub.so -Wl,-rpath=target/
