from pwn import *

seq = cyclic(5000).decode()
print(seq)

print("\n---\n")
overflow = cyclic_find("aadi")  # rax before cmp eax, 0x539
print(overflow)

print("\n---\n")
overflow = cyclic_find("aaqo")
print(overflow)

print("\n---\n")
# IDA code:
text = """
.text:08049ECC                 lea     esp, [ebp-0Ch]
.text:08049ECF                 pop     ecx
.text:08049ED0                 pop     ebx
.text:08049ED1                 pop     edi
.text:08049ED2                 pop     ebp
.text:08049ED3                 lea     esp, [ecx-4]
.text:08049ED6                 retn
"""
lines = text.strip().split('\n')
addresses = ["0x" + line.split(' ')[0].split(':')[1] for line in lines]
for addr in addresses:
    print("br *" + addr)
