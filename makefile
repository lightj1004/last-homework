all:
	gcc -o read_cap hw3.c -lpcap
clean:
	rm read_cap 