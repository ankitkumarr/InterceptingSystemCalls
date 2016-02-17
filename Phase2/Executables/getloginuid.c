#include  <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#define __NR_cs3013_syscall1 355
#define __NR_cs3013_syscall2 356
#define __NR_cs3013_syscall3 357

long testCall3 (unsigned short *pid, unsigned short *uid) {

	return (long) syscall(__NR_cs3013_syscall3, pid, uid);
}

int main(int argc, char ** argv) {

	if(argc!= 2) {
		printf("\n USAGE: ./getloginuid <process_number>\n");
		exit(1);
	}
	unsigned short *uid = (unsigned short*)malloc(sizeof(unsigned short));
	unsigned short *pid = (unsigned short*)malloc(sizeof(unsigned short));
	*pid = atoi(*(argv+1));
	long ret = testCall3(pid, uid);
	printf("\tcs3013_syscall1: %ld\n", ret);
	if(ret==0) {
		printf("\t The process is owned by %d\n", *uid);
	}
	else {
		printf("\tError! Could not find the user \n");
	}
	return 0;
}


