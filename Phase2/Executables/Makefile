all: getloginuid shift2user

getloginuid: getloginuid.o
	gcc -g getloginuid.o -o getloginuid

getloginuid.o: getloginuid.c
	gcc -g -c getloginuid.c

shift2user: shift2user.o
	gcc -g shift2user.o -o shift2user

shift2user.o: shift2user.c
	gcc -g -c shift2user.c

clean:
	rm -rf shift2user getloginuid *.o
