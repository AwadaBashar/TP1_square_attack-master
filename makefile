C=gcc
CFLAGS=
LDFLAGS=
EXEC=q2 q1 q3 aes128_attack

all: $(EXEC)

q2: q2.o helpers.o aes-128_enc.o
		$(CC) -o $@ $^ $(LDFLAGS)

q1: q1.o helpers.o aes-128_enc.o
		$(CC) -o $@ $^ $(LDFLAGS)

q3: q3.o helpers.o aes-128_enc.o
		$(CC) -o $@ $^ $(LDFLAGS)

aes128_attack: aes128_attack.o helpers.o aes-128_enc.o
		$(CC) -o $@ $^ $(LDFLAGS)

*.o: *.c
		$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean
clean:
		rm -rf *.o