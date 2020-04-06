#include <features.h>

#define START "_start"

#include "crt_arch.h"


#ifdef STACK_RELOC
#define _GNU_SOURCE
#include "stack_arch.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "syscall.h"
#include <sys/prctl.h>
#include <elf.h>

#if ULONG_MAX == 0xffffffff
typedef Elf32_auxv_t Auxv;
typedef Elf32_Ehdr Ehdr;
#else
typedef Elf64_auxv_t Auxv;
typedef Elf64_Ehdr Ehdr;
#endif
#endif /* STACK_RELOC */


int main();
void _init() __attribute__((weak));
void _fini() __attribute__((weak));
_Noreturn int __libc_start_main(int (*)(), int, char **,
	void (*)(), void(*)(), void(*)());


#ifdef STACK_RELOC_DEBUG
static inline char *_itoa_b16(char *p, unsigned long x)
{
	p += (sizeof(unsigned long)*2) +1 +1;
	*--p = 0;
	*--p = '\n';
	do {
		char c = x % 16;
		*--p = (c < 10) ? ('0' + c) : ('a' + c -10);
		x /= 16;
	} while (x);
	return p;
}
static inline char *_itoa_b10(char *p, long x)
{
	char sign =0;
        p += 20 +1 +1;
	*--p = 0;
	*--p = '\n';
	if (x < 0) {
		x *= -1;
		sign =1;
	}
	do {
		*--p = '0'+ x % 10;
		x /= 10;
		} while (x);
	if (sign)
		*--p = '-';
	return p;
}
#endif /* STACK_RELOC_DEBUG */


void _start_c(long *p)
{
	register int argc = p[0];
	register char **argv = (void *)(p+1);

#ifdef STACK_RELOC
	/* stack relocation code */
	register char **envp = argv+argc+1;
	Auxv *auxv; 
	int i, copied =-1, size =-1, total_size =-1;
	long stack_ptr =-1, stack_addr =-1;
	register long max; long vvar_base, vdso_size;
	Ehdr *sysinfo_ehdr;

	/* ARCH getting the the current stack pointer */
	stack_ptr = arch_stack_get();

	/* check if relocation is not needed. This may happen when the current
	 * stack is below the requested stack address.
	 */
	if ( STACK_START_ADDR > (unsigned long) stack_ptr)
		goto _abort_relocation;
    
	/* getting the current dimension of the stack, using heuristics */
	for (i=0; i<argc; i++) {
		if (max < (long)argv[i])
			max = (long)argv[i];
	}
	for (i=0; envp[i]; i++) {
		if (max < (long)envp[i])
			max = (long)envp[i];
	}
	auxv = (Auxv *)(&envp[i+1]);
	for (i=0; (auxv[i].a_type != AT_NULL); i++) {
		if (max < (long)auxv[i].a_un.a_val)
			max = (long) auxv[i].a_un.a_val;

	/* look for VDSO information */
	if ( (auxv[i].a_type == AT_SYSINFO_EHDR) ) /* TODO maybe consider AT_SYSINFO as well */
	    sysinfo_ehdr = (Ehdr*)auxv[i].a_un.a_val;

	/* check if we need to abort relocation, for example in case of dynamic 
	 * linking. The key heuristic is to check if the text section is above
	 * the new stack address -- as we don't relocate the text section, we 
	 * need to abort.
	 */
	if ( (auxv[i].a_type == AT_ENTRY) &&
			(auxv[i].a_un.a_val >= STACK_END_ADDR) )
		goto _abort_relocation;
	}
	/* align max address */
	max = (max & ~(STACK_PAGE_SIZE -1)) + STACK_PAGE_SIZE;
	size = (max - ((unsigned long)stack_ptr) ); 

	/* update expected total mapped size in [stack] */
	total_size = STACK_PAGE_SIZE * (STACK_MAPPED_PAGES + (size/STACK_PAGE_SIZE) +1); //it is ok to over estimate this
    
	/* if VDSO is mapped in, let's move it firstly */
	if (sysinfo_ehdr) {
		/* VDSO: need to look up the size in the phdr and align it */
		Elf64_Phdr *ph = (void *)((char *)sysinfo_ehdr + sysinfo_ehdr->e_phoff);
		size_t base=-1i, end =-1;
		for (i=0; i<sysinfo_ehdr->e_phnum; i++, ph=(void *)((char *)ph+sysinfo_ehdr->e_phentsize)) {
			/* so far, kernel version 5.15 there is only one PT_LOAD, this doesn't support more than one */
			if (ph->p_type == PT_LOAD) {
				base = (size_t)sysinfo_ehdr + ph->p_offset - ph->p_vaddr;
				end = base + ph->p_memsz;
				if (end & (STACK_PAGE_SIZE -1))
					end = (end & ~(STACK_PAGE_SIZE -1)) + STACK_PAGE_SIZE;
			}
		}
		if (!base || !end)
			goto _malformed_vdso;

		/* VVAR: it is before the VDSO, get the size by using a macro */
		vvar_base = base - arch_vvar_get_pagesz();

		/* remap VVAR and VDSO together at the end of the rebuilt address space */
		stack_addr = __syscall(SYS_mremap, vvar_base, (base - vvar_base), (base - vvar_base), (MREMAP_FIXED | MREMAP_MAYMOVE), STACK_END_ADDR - (end- vvar_base));
		if ( ((unsigned long) stack_addr) > -4096UL) {
			i =1; goto _error;
		}

		stack_addr = __syscall(SYS_mremap, base, (end - base), (end - base), (MREMAP_FIXED | MREMAP_MAYMOVE), STACK_END_ADDR - (end - base));
		if ( ((unsigned long) stack_addr) > -4096UL) {
			i =2; goto _error;
		}

		/* update max, size, total size */
		vdso_size = (end - vvar_base);
    }
_malformed_vdso:

#if STACK_RELOC_USE_MMAP
    /* get the memory for the stack */

    //TODO implement the same trick as with mremap (see below)

#ifdef SYS_mmap2
    stack_addr = (void*) __syscall(SYS_mmap2, STACK_START_ADDR - vdso_size, STACK_SIZE, PROT_READ|PROT_WRITE, (MAP_PRIVATE|MAP_ANON|MAP_FIXED), -1, 0);
#else /* SYS_mmap2 */
    stack_addr = (void*) __syscall(SYS_mmap, STACK_START_ADDR - vdso_size, STACK_SIZE, PROT_READ|PROT_WRITE, (MAP_PRIVATE|MAP_ANON|MAP_FIXED), -1, 0);
#endif /* !SYS_mmap2 */
	if ( ((unsigned long) stack_addr) > -4096UL) {
		i =3; goto _error;
	}
	memset(stack_addr, STACK_SIZE, 0);
#endif /* STACK_RELOC_USE_MMAP */
    
	/* rewrite pointers for the new stack */
	for (i=0; i<argc; i++)
		argv[i] = (void*) (STACK_END_ADDR - vdso_size - (max - (unsigned long) argv[i])); 
	for (i=0; envp[i]; i++)
		envp[i] = (void*) (STACK_END_ADDR - vdso_size - (max - (unsigned long) envp[i]));
	for (i=0; (auxv[i].a_type != AT_NULL); i++)
		switch (auxv[i].a_type) {
		case AT_PHDR: case AT_BASE: case AT_ENTRY:
		case AT_PLATFORM: case AT_BASE_PLATFORM:
		case AT_EXECFN: case AT_RANDOM: 
			/* check if it is != 0 and greater than the new stack end addr */
			if (auxv[i].a_un.a_val > STACK_END_ADDR)
				auxv[i].a_un.a_val = STACK_END_ADDR - vdso_size - (max - auxv[i].a_un.a_val);

		/* we don't do VDSO relocation for now (TODO fix when we do VDSO relocation) */
		case AT_SYSINFO: case AT_SYSINFO_EHDR:
			if (vdso_size && auxv[i].a_un.a_val)
				auxv[i].a_un.a_val = STACK_END_ADDR - vdso_size + arch_vvar_get_pagesz();
		/* all others handled by the kernel */
		case AT_HWCAP: case AT_PAGESZ: case AT_CLKTCK: case AT_PHENT:
		case AT_PHNUM: case AT_FLAGS: case AT_UID: case AT_EUID:
		case AT_GID: case AT_EGID: case AT_SECURE: case AT_EXECFD:
		case AT_HWCAP2:
			break;
		}
	/* update pointers with the new address */
	argv = (void*) (STACK_END_ADDR - vdso_size - ((unsigned long)max - (unsigned long) argv));
	envp = (void*) (STACK_END_ADDR - vdso_size - ((unsigned long)max - (unsigned long) envp));
	auxv = (void*) (STACK_END_ADDR - vdso_size - ((unsigned long)max - (unsigned long) auxv)); // i includes the number of auxvs

#if STACK_RELOC_USE_MMAP
	/* ARCH copy of the stack */ //TODO can we use SYS_mremap instead?
	copied = __memcpy_nostack((STACK_END_ADDR - vdso_size -size), stack_ptr, size);
	if (copied != size) {
		i =4; goto _error;
	}
#else /* STACK_RELOC_USE_MMAP */
__retry_mremap:
	/* try mremap */
	stack_addr = __syscall(SYS_mremap, (max - total_size), total_size, total_size, (MREMAP_FIXED | MREMAP_MAYMOVE), STACK_END_ADDR - vdso_size - total_size);
	if ( ((unsigned long) stack_addr) > -4096UL) {
		/*
		 * Here we use another pseudo heuristic from the Linux kernel.
		 * When execve the kernel mm_init a stack of one page, then 
		 * in setup_arg_pages it extends it, the extension is 32 pages
		 * that takes it to 33, however, sometimes is 34 (on aarch64 at 
		 * least). Setting ulimit may also end up in a smaller stack. We
		 * try to guess the size here.
		 */
		if (total_size >  size) {
			total_size -= STACK_PAGE_SIZE;
			goto __retry_mremap;
		}
		i =4; goto _error;
	}
#endif /* !STACK_RELOC_USE_MMAP */

	/* tells to the kernel where is the stack */
	// printf("[yfzm] Summary: stack_end_addr: %p\n", STACK_END_ADDR -vdso_size - total_size);
	// printf("[yfzm] Summary: env_end_addr: %p\n", STACK_END_ADDR -vdso_size);
	__syscall(SYS_prctl, PR_SET_MM, PR_SET_MM_START_STACK, (STACK_END_ADDR -vdso_size - total_size), 0, 0);
	__syscall(SYS_prctl, PR_SET_MM, PR_SET_MM_ARG_START, argv[0], 0, 0);
	__syscall(SYS_prctl, PR_SET_MM, PR_SET_MM_ARG_END,   envp[0], 0, 0);
	__syscall(SYS_prctl, PR_SET_MM, PR_SET_MM_ENV_START, envp[0], 0, 0);	
	__syscall(SYS_prctl, PR_SET_MM, PR_SET_MM_ENV_END,   STACK_END_ADDR -vdso_size, 0, 0);
	__syscall(SYS_prctl, PR_SET_MM, PR_SET_MM_AUXV,      &auxv[0], i*sizeof(Auxv), 0);

	/* mmap protect upper area */
	__syscall(SYS_mmap, STACK_END_ADDR, arch_vaddr_max() - STACK_END_ADDR, 0, (MAP_PRIVATE|MAP_ANON|MAP_FIXED), -1, 0);

	/* ARCH stack switch */
	arch_stack_switch(STACK_END_ADDR -vdso_size, size);

#if STACK_RELOC_USE_MMAP
	/* unmap previous stack */
	__syscall(SYS_munmap, (max - total_size), total_size);
#endif /* STACK_RELOC_USE_MMAP */
	
	/* WARNING here local variables may not work */
	
_abort_relocation:
#endif /* STACK_RELOC */

	/* now continue to normal startup */
	__libc_start_main(main, argc, argv, _init, _fini, 0);

#ifdef STACK_RELOC
	/* we should reach here only in case of errors */
_error:
{
	char serror [] = "crt1.c: _start_c ERROR 0\n";
	char verror [22];
	serror[23] += i;
	__syscall(SYS_write, 2, serror, strlen(serror));

#ifdef STACK_RELOC_DEBUG
	memset(verror, '0', sizeof(unsigned long)*2 +1);
	_itoa_b16(verror, (unsigned long) max);
	__syscall(SYS_write, 2, verror, strlen(verror));

	memset(verror, '0', sizeof(unsigned long)*2 +1);
	_itoa_b16(verror, (unsigned long) total_size);
	__syscall(SYS_write, 2, verror, strlen(verror));

	memset(verror, '0', 20);
	_itoa_b10(verror, (long) stack_addr);
	__syscall(SYS_write, 2, verror, strlen(verror));

	while(1){}; //debugging trap
#endif /* STACK_RELOC_DEBUG */
}
    /* from src/exit/_Exit.c */
    //int ec =1;
    __syscall(SYS_exit_group, 1); //ec);
    for (;;) __syscall(SYS_exit, 1); //ec);
#endif /* STACK_RELOC */
}
