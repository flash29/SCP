

all: program1 program2

program1: program1.c printing.c
	cc program1.c printing.c -o program1

program2: program2.c printing.c
	cc program2.c printing.c -o program2

clean:
	rm program1 program2