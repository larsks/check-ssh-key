CFLAGS = -g
LIBS = -lssh2

all: check_ssh_key

check_ssh_key: check_ssh_key.o
	$(CC) -o $@ $< $(LIBS)

clean:
	rm -f check_ssh_key.o

