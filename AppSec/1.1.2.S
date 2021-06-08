.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here
#subl $12, %esp					# make room on stack for args
#movl $0xc001f00d, -0x4(%ebp)			# mp argument (was -4, -8 -0xc)
#movl $0xc105ed, -0x8(%ebp)			# sec argument
#movl $0xacce55ed, -0xc(%ebp)			# app argument
push $0xc001f00d
push $0xc105ed
push $0xacce55ed
call practice
addl $12, %esp					# pop args from stack
leave
ret
