/*
  Credit: YiFei Zhu

  This file provides a way to build/run your shellcode as a standalone executable, which can
  be easier to debug than when you have to inject it into the vulnerable program, like you
  must in your final solution.

  This file will NOT be used in grading. Partial credit will NOT be awarded
  based on the contents of this file. It is only to help you work on your final
  solution to 1.2.11

  Assuming this assembly file is called 1.2.11_helper.S

  To build standalone executable:
    $ gcc -DTEST 1.2.11_helper.S -o 1.2.11_helper

    The generated standalone ELF (executable) is 1.2.11_helper. Do whatever you
    need with it to complete 1.2.11
    Ex: check for null bytes:
    $ objdump -d ./1.2.11_helper | awk -v RS= '/<main>:/' | grep ' 00 '

  To build shellcode:
    $ gcc -static -nostartfiles -Wl,--section-start=.text=0x[BASE ADDRESS OF SHELLCODE GOES HERE, WITHOUT THE BRACKETS] 1.2.11_helper.S -o 1.2.11_helper.o
    $ objcopy -j .text -O binary 1.2.11_helper.o 1.2.11_helper

    The generated shellcode in flat binary form is 1.2.11_helper. Do whatever you
    need with it to complete 1.2.11, such as creating a python representation:
    $ python3 -c 'print(repr(open("1.2.11_helper", "rb").read()))'
    or to check for null bytes:
    $ hd 1.2.11_helper | grep ' 00 '
*/

#ifdef TEST
.globl main
main:

// Function prologue, used if built as standalone executable
push %ebp
mov %esp,%ebp
#else
.globl _start
_start:
#endif

// YOUR ASSEMBLY GOES HERE

#ifdef TEST
leave
ret

.data
#endif

// YOUR LABELED DATA GOES HERE, LIKE
label:
.long 0xABCD123

end:

