CFLAGS = -g
LIBS = libssh2.a -lssl #-lefence

all: check_ssh_key

check_ssh_key: check_ssh_key.o
	$(CC) -o $@ $< $(LIBS)

clean:
	rm -f check_ssh_key.o

