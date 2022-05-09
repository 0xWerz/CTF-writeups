# TIPS AND TRICKS 247/CTF | 0xWerz | 08/07/22

### The Official preview
> A number of challenges will require you to create solutions which are more efficiently solved by making use of a programming language to automate and perform the computations. For this purpose, we recommend to make use of PYTHON as well as complementary libraries such as REQUESTS and PWNTOOLS.

>If you are not sure where to start with Python, we recommend the introductory PYTHON 101 FOR HACKERS course.

>Click the ‘START CHALLENGE’ button to the right of this text description to start a socket challenge. Utilise a programming language to interface with the socket and automate solving 500 simple addition problems to receive the flag. Take care when interfacing with unknown remote services - '\n' is not the only way to end


well, what we are trying to do is pretty simple.

we need to automate a 500 simple math operations, and they have mentioned/recommended to use python, imma use the pwn library its pretty easy also.

## The solution

``` python
from pwn import *

url = '595edc7e7ff44d36.247ctf.com'
port = '50415'

client = remote(url, port)

print(client.recvline())
print(client.recvline())
for i in range(500):
    problem = client.recvline().decode("utf-8")
    
    indexing = problem.split()

    Qa = int(indexing[5])
    Qb = int(indexing[7].strip('?'))
    answer = (str(Qa+Qb)+ '\r\n').encode("utf-8")
    print(f'answering {i} question ({Qa ,"+", Qb})...')
    client.sendline(answer)
    client.recvline()
flag = client.recvline().decode("utf-8").strip('\r\n')

print("Catched the flag!",flag)

client.close()
```
