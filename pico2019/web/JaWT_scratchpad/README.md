![title](images/title.png)

JWT is a JSON Web Token that can be disected using base64. Its comprised of 3 parts

HEADER - PAYLOAD - VERIFY SIGNATURE.

The signature can be bruteforced with john the ripper if we're lucky so lets give that a shot.


**ppython3 jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdCJ9.IAu_YSHppFe8hXH_BSPb4OLJYGUi8wXqXdS0T33cKbA > jwt.txt**



**john jwt.txt --wordlist=~/rockyou.txt**

```
~/ctf_writeups/pico2019/web/JaWT_scratchpad# john jwt.txt --show
?:ilovepico

1 password hash cracked, 0 left
```

Navigate to https://jwt.io/ and put in the token changing the user and secret key fields then use burpe to submit and get our flag

<details>
	<summary>Flag</summary>

picoCTF{jawt_was_just_what_you_thought_c84a0d3754338763548dfc2dc171cdd0
</details>

