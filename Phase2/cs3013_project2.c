#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

unsigned long **sys_call_table;

asmlinkage long (*ref_sys_cs3013_syscall1)(void);
asmlinkage long (*ref_sys_cs3013_syscall2)(unsigned short *target_pid, unsigned short *target_uid);
asmlinkage long (*ref_sys_cs3013_syscall3)(unsigned short *target_pid, unsigned short *actual_uid);
int searchprocess (struct task_struct *task, unsigned short *processid, unsigned short *userid);
unsigned short *searchprocess2 (struct task_struct *task, unsigned short *processid, unsigned short *userid);


asmlinkage long new_sys_cs3013_syscall1(void) {
	printk(KERN_INFO "\"'Hello world?!' More like 'Goodbye, world!' EXTERMINATE!\" -- Dalek");
	return 0;
}

asmlinkage long new_sys_cs3013_syscall2(unsigned short *target_pid, unsigned short *target_uid) {

	//to store the return value	
	int ret;

	//allocating the pointers
	unsigned short *u_target_pid = (unsigned short*) kmalloc (sizeof (unsigned short), GFP_KERNEL);
	unsigned short *u_target_uid = (unsigned short*) kmalloc (sizeof (unsigned short), GFP_KERNEL);

	//copy from user to kernel space
	if (copy_from_user(u_target_pid, target_pid, sizeof(unsigned short))) {
		return EFAULT;
	}

	//copy from user to kernel space
	if (copy_from_user(u_target_uid, target_uid, sizeof(unsigned short))) {
		return EFAULT;
	}

	//Searching the process with the target_pid starting from init
	ret = searchprocess(&init_task, u_target_pid, u_target_uid);	

	//an error encountered somewhere
	if(ret==1) {
		printk("\nError at syscall 2. Possible error: Process not found\n");
	}

	if(ret == 0) {
		printk("\t The process was found and successfully implemented the desired change\n");
	}
	return ret;
}

asmlinkage long new_sys_cs3013_syscall3(unsigned short *target_pid, unsigned short *actual_uid) {
	
	//allocating the pointers
	unsigned short *u_target_pid = (unsigned short *)kmalloc(sizeof (unsigned short), GFP_KERNEL);
	unsigned short *target_pidfound = (unsigned short *)kmalloc(sizeof (unsigned short), GFP_KERNEL);

	//this was sent from the user space and hence needs to be copied to the kernel space
	if (copy_from_user(u_target_pid, target_pid, sizeof(unsigned short))) {
		return EFAULT;
	}

	//find the process with the given id starting from init
	target_pidfound = searchprocess2(&init_task, u_target_pid, actual_uid);

	//Error
	if (target_pidfound == NULL) {
		printk("Error in syscall3\n");
		return 1;
	}
	
	//copying to user space so that user can access the pointer
	if (copy_to_user(actual_uid, target_pidfound, sizeof(unsigned short))) {
		return EFAULT;
	}


	return 0;

}

static unsigned long **find_sys_call_table(void) {
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *) sys_close) {
			printk(KERN_INFO "Interceptor: Found syscall table at address: 0x%02lX",
					(unsigned long) sct);
			return sct;
		}

		offset += sizeof(void *);
	}

	return NULL;
}

static void disable_page_protection(void) {
	/*
	   Control Register 0 (cr0) governs how the CPU operates.

	   Bit #16, if set, prevents the CPU from writing to memory marked as
	   read only. Well, our system call table meets that description.
	   But, we can simply turn off this bit in cr0 to allow us to make
	   changes. We read in the current value of the register (32 or 64
	   bits wide), and AND that with a value where all bits are 0 except
	   the 16th bit (using a negation operation), causing the write_cr0
	   value to have the 16th bit cleared (with all other bits staying
	   the same. We will thus be able to write to the protected memory.

	   It's good to be the kernel!
	 */
	write_cr0 (read_cr0 () & (~ 0x10000));
}

static void enable_page_protection(void) {
	/*
	   See the above description for cr0. Here, we use an OR to set the 
	   16th bit to re-enable write protection on the CPU.
	 */
	write_cr0 (read_cr0 () | 0x10000);
}

static int __init interceptor_start(void) {
	/* Find the system call table */
	if(!(sys_call_table = find_sys_call_table())) {
		/* Well, that didn't work. 
		   Cancel the module loading step. */
		return -1;
	}

	/* Store a copy of all the existing functions */
	ref_sys_cs3013_syscall1 = (void *)sys_call_table[__NR_cs3013_syscall1];
	ref_sys_cs3013_syscall2 = (void *)sys_call_table[__NR_cs3013_syscall2];
	ref_sys_cs3013_syscall3 = (void *)sys_call_table[__NR_cs3013_syscall3];

	/* Replace the existing system calls */
	disable_page_protection();

	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)new_sys_cs3013_syscall1;
	sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)new_sys_cs3013_syscall2;
	sys_call_table[__NR_cs3013_syscall3] = (unsigned long *)new_sys_cs3013_syscall3;

	enable_page_protection();

	/* And indicate the load was successful */
	printk(KERN_INFO "Loaded interceptor!");

	return 0;
}

static void __exit interceptor_end(void) {
	/* If we don't know what the syscall table is, don't bother. */
	if(!sys_call_table)
		return;

	/* Revert all system calls to what they were before we began. */
	disable_page_protection();
	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)ref_sys_cs3013_syscall1;
	sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)ref_sys_cs3013_syscall2;
	sys_call_table[__NR_cs3013_syscall3] = (unsigned long *)ref_sys_cs3013_syscall3;
	enable_page_protection();

	printk(KERN_INFO "Unloaded interceptor!");
}

//This function searches the process with the given process id and replaces the userid if eligible
int searchprocess (struct task_struct *task, unsigned short *processid, unsigned short *userid) {
	struct task_struct *child;
	unsigned short cpid;

	//flag variable to check for success
	int flag = 1;
	int cuid;
	//marco to loop through all the children of the task_struct task
	list_for_each_entry (child, &(task->tasks), tasks) {
		//printk("Test1 at entry \n");
		cpid = (unsigned short) child->pid;
		if (cpid  == *processid) {
			printk("\tProcess found with ID %d\n", cpid);

			cuid = current_uid().val;

			//checking if root user or not
			if(cuid < 1000) { 
				printk("\t Current user identified as a root user\n");
				(child->loginuid).val = *userid;
			}
			else {
				if(cuid == (child->loginuid).val || child->loginuid.val == (-1) || child->loginuid.val == 65535) {
					if(*userid ==1001) {
						printk("\t Moving process id %d to userid %d\n",cpid, *userid);
						(child->loginuid).val = *userid;
					}
					else {
						flag = 1;
						printk("\t This user is not authorized to move process to any users but 1001\n");
						break;
					}
				}
				else {
					flag = 1;
					printk("Cannot change processes not owned by the user cuid = %d and %d \n", cuid, (child->loginuid).val);
					break;
				}
			}

			flag = 0;
			printk("\tProcess change successful\n");
			break;
		}
	}
	//printk("Test3 right before return \n");
	return flag;
	//printk("No Processes found, exiting");

}


//This function goes through the task and tracks down the processid. It then finds the userid and returns the pointer
unsigned short *searchprocess2 (struct task_struct *task, unsigned short *processid, unsigned short *userid) {
	struct task_struct *child;
	unsigned short *sp = (unsigned short *)kmalloc(sizeof(unsigned short),GFP_KERNEL);
//	unsigned short *test;
	list_for_each_entry (child, &(task->tasks), tasks) {
		unsigned short cpid = (unsigned short) child->pid;
		if (cpid  == *processid) {
			printk("\t Found the process with id %d\n", cpid); 
			//unsigned short *sp = (unsigned short*) kmalloc(sizeof(unsigned short),GFP_KERNEL);
			*sp = (child->loginuid).val; 
			return sp;
		}
		//test = (unsigned short *)kmalloc(sizeof(unsigned short),GFP_KERNEL);

	}
	return NULL;
}

MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);
