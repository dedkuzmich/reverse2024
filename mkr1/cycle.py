from pwn import *

seq = cyclic(3000).decode()
print(seq)

print("\n---\n")

overflow = cyclic_find(0x69646161)  # rax before cmp eax, 0x539
print(overflow)

print("\n---\n")

# IDA code:
text = """
.text:0804A077 lea     esp, [ebp-10h]
.text:0804A07A pop     ecx
.text:0804A07B pop     ebx
.text:0804A07C pop     esi
.text:0804A07D pop     edi
.text:0804A07E pop     ebp
.text:0804A07F lea     esp, [ecx-4]
.text:0804A082 retn
"""
lines = text.strip().split('\n')
addresses = ["0x" + line.split(' ')[0].split(':')[1] for line in lines]
for addr in addresses:
    print("br *" + addr)
