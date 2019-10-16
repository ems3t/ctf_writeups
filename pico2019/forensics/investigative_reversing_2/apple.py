#!/usr/bin/env python

with open('./encoded.bmp', 'rb') as f:
	data = f.read()

offset = 2000
data = data[offset:offset+(50*8)]

flag = ''

for i in range(0x32):
	j = 0
	for k in range(8):
		j = j | (ord(data[i*8+(7-k)])&1)
		j = j << 1
	j = j >> 1
	flag += chr(j+5)
print flag
