![title](images/title.png)

I began the challenge by just exploring the site, creating a user and loggin in. I noticed you can list employees so I tried logging in as one of them with a weak password(their username)

```
1 	jarrett.booz 	Jarrett Booz
2 	danny.tunitis 	Danny Tunitis
3 	a1extt 	a1extt
4 	a 	a
5 	testing 	testing
```

Didnt work. Lets move on to sqli with the TODO cards

I had trouble with this one and had to get some help with the sqli attack

[Source[](https://github.com/bleh05/pico19writeup/tree/master/Empire1)

```sql
'||(select group_concat(secret) from user)||'
```

<details>
	<summary>Flag</summary>

picoCTF{wh00t_it_a_sql_inject46527b2c}
</details>