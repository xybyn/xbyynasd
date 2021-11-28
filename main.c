#include <stdio.h>
#include <stdlib.h>

#include "myTraceroute.h"

int main(int argc, char* argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Errror: need destination for traceroute!\n");
		exit(EXIT_FAILURE);
	}
	else
		myTraceroute(argv[1]);

	return 0;
}
