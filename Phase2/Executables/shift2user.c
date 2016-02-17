#include  <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#define __NR_cs3013_syscall1 355
#define __NR_cs3013_syscall2 356
#define __NR_cs3013_syscall3 357

long testCall2 (unsigned short *pid, unsigned short *uid) {

	return (long) syscall(__NR_cs3013_syscall2, pid, uid);
}

int main(int argc, char ** argv) {
	
	if(argc!=3) {
		printf("\n USAGE: send2user <process_id> <user_id>\n");
		exit(1);
	}
	unsigned short *uid = (unsigned short*)malloc(sizeof(unsigned short));
	unsigned short *pid = (unsigned short*)malloc(sizeof(unsigned short));
	*pid = atoi(*(argv+1));
	*uid = atoi(*(argv+2));
	long ret = testCall2(pid, uid);
	printf("\tcs3013_syscall2: %ld\n", ret);
	if(ret == 0) {
		printf("send2user was successful! The request was completed\n");
	}
	else {
		printf("Error! send2user could not finish your request. Please check the syslog for more info!\n");
	}
	return 0;
}


