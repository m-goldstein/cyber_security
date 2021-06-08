.global your_asm_fn
.section .data
coolfood: .ascii "coolfood\00"
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here
# caller-save registers
pushl %eax
pushl %ecx
pushl %edx

pushl $coolfood
movl %esp, %eax			# third argument addres into EAX
pushl $0xc105ed
movl  %esp, %ecx		# second argument address into ECX
pushl (%eax)			# push third arg (starting memory address of coolfood string) onto stack
pushl %ecx			# push second arg (memory address of *sec argument) onto stack
pushl $0xacce55ed		# push first argument onto stack
call practice
addl $12, %esp			# pop arguments from stack
addl $8, %esp			# equivalent to popping twice to restore ESP location
				# need to balance number of push/pop operations
# restore caller-save registers
popl %edx
popl %ecx
popl %eax
leave
ret
