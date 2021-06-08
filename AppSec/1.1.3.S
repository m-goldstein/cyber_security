.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here
pushl $0xc001f00d			# put first argument on stack
movl  %esp, %eax			# put address into eax
pushl %eax				# push reference onto stack (as mp argument)
pushl $0xc105ed				# push second arg onto stack
pushl $0xacce55ed			# push first argument onto stack
call practice				# invoke function practice
addl $12, %esp				# pop arguments onto stack
popl %eax				# restore eax (to balance push/pop operations)
leave					# return to caller frame
ret
