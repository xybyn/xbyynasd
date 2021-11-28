DEFINES = -D_POSIX_C_SOURCE -D_BSD_SOURCE
CFLAGS  = -std=c99 -g $(DEFINES)

myTraceroute: main.o myTraceroute.o 
	gcc $(CFLAGS) -o myTraceroute main.o myTraceroute.o
main.o: main.c myTraceroute.h
	gcc $(CFLAGS) -c main.c
myTraceroute.o: myTraceroute.c myTraceroute.h
	gcc $(CFLAGS) -c myTraceroute.c

clean:
	rm -rf *.o main
