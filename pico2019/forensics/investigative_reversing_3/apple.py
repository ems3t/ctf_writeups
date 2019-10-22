#!/usr/bin/env python3

flag = ''
with open('./encoded.bmp', 'rb') as f:
	f.seek(0x2d3)

	for i in range(100):
		if i & 1 == 0:
			b = ""
			for j in range(8):
				data = f.read(1)
				b+= str(int.from_bytes(data, 'big') & 1)
			c = int(b[::-1], 2)
			flag+= (chr(c))
		else:
			f.read(1)
print (flag)