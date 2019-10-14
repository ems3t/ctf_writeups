# Extensions (Forensics)

![title](images/title.png)

Based on the title I can only assume the file extension is messed up so I'll run
on the file

```bash
file flag.txt
```
```
flag.txt: PNG image data, 1697 x 608, 8-bit/color RGB, non-interlaced
```

Lets rename it and see if we can open with eog

```bash
mv flag.txt flag.png
eog flag.png
```

Success..

<details>
	<summary>Flag</summary>

picoCTF{now_you_know_about_extensions}
</details>