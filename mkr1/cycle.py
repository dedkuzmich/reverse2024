from pwn import *


def get_breaks(code):
    lines = code.strip().split('\n')
    for line in lines:
        addr = line.split(":")[1].split(" ")[0]
        print(f"br *0x{addr}")


def main():
    # Create de Bruijn sequence
    seq = cyclic(5000).decode()
    print(seq)

    print("\n------------")
    print(cyclic_find("aadi"))  # rax before cmp eax, 0x539

    print("\n------------")
    print(cyclic_find("aaqo"))

    print("\n------------")
    # IDA code:
    code = """
    .text:08049ECC                 lea     esp, [ebp-0Ch]
    .text:08049ECF                 pop     ecx
    .text:08049ED0                 pop     ebx
    .text:08049ED1                 pop     edi
    .text:08049ED2                 pop     ebp
    .text:08049ED3                 lea     esp, [ecx-4]
    .text:08049ED6                 retn
    """
    get_breaks(code)


if __name__ == "__main__":
    main()
