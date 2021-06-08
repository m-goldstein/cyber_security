.global _main
# need to store the string in .data segment
.section .data
filename: .ascii "/bin/sh\00"

.section .text

_main:

push    %ebp
mov     %esp,%ebp

# Your code here

# caller-save registers
pushl %eax
pushl %ecx
pushl %edx

addl $-0x8, %esp				# make room on stack for char *const argv[] argument
movl $filename, %ebx				# move filename string base address into EBX
movl %ebx, -0x8(%ebp)				# move filename starting address into first argv entry
movl $0x00, -0x4(%ebp)				# move NULL into second argv entry

movl %ebp, %ecx					# move argv[] base address into ECX
addl $-0x8, %ecx				# adjust ECX by 8 to point to start of argv[]
movl $0x00, %edx				# move envp parameter (NULL) into EDX
movl $0xb, %eax					# set system call number to 11 
						#(see https://github.com/torvalds/linux/blob/v4.17/arch/x86/entry/syscalls/syscall_32.tbl#L17)
int $0x80					# invoke system call (%eax -- return value), 
                                                # (%ebx -- first arg, %ecx -- second arg, %edx -- third arg)

addl $0x8, %esp					# pop temp. variables from stack

# restore registers
popl %edx
popl %ecx
popl %eax

leave
ret
