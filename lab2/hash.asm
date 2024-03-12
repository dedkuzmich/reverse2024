;; Compile:
;; $ nasm -f win64 exp.asm -o exp.obj && gcc exp.obj -o exp.exe && ./exp.exe
;; Format:
;; $ nasmfmt -oi 12 exp.asm
        bits        64

        extern      puts
        extern      strlen
        extern      _ui64toa
        extern      system
        extern      strcmp

        extern      GetStdHandle
        extern      WriteFile
        extern      ExitProcess
        extern      StringCchCopyA

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


        %define     utf16(x) __?utf16?__(x)    ; UTF-16 macros
        section     .data
STD_OUTPUT_HANDLE:
        dq          -11

endl:
        db          10, 0

szPause:
        db          "pause", 0

utf16Path:
        dw          utf16('C:\WINDOWS'), 0     ; UTF-16 string

szMsg1:
        db          "msg1", 10, 0

szMsg2:
        db          "msg2", 10, 0

szMsg3:
        db          "msg3", 10, 0

szWinExec:
        db          "WinExec", 0               ; kernel32.dll
        ; db          "CsrAllocateCaptureBuffer", 0       ; ntdll.dll

szCalc:
        db          "calc.exe", 0

WIN:
        db          10, "WIN", 10, 0

task:
        db          10, "Name idx -> ordinal -> addr", 10, 0



        section     .bss
szBuffer:
        resb        24

buf:
        resq        1



        section     .text
;; void WinMain()
WinMain:
        save_regs  
        %push       proc_context
        %stacksize  flat64
        %assign     %$localsize 64
        %local      iNum1:qword
        %local      iNum2:qword
        %local      iNum3:qword

        %local      pWinExec:qword
        %local      iHash:qword
        enter       %$localsize, 0


        lea         rcx, [szWinExec]
        call        PrintStr
        lea         rcx, [endl]
        call        PrintStr


        lea         rcx, [szWinExec]
        call        Ror13
        mov         qword [iHash], rax

        mov         rcx, qword [iHash]
        mov         rdx, 16
        call        PrintNum


        leave      
        restore_regs
        ret        
        %pop       



;; int Ror13 (PSTR pStr)
;; pStr = rcx
Ror13:
        save_regs  
        %push       proc_context
        %stacksize  flat64
        %assign     %$localsize 64
        %local      pStr:qword
        enter       %$localsize, 0

        mov         qword [pStr], rcx

        ; Hash loop
        mov         r10, qword [pStr]
        mov         r11, 0                     ; Counter
        mov         r12, 0                     ; Hash
.next_byte:
        mov         rbx, 0
        mov         bl, byte [r10 + r11]       ; Read a byte from string
        cmp         rbx, 0                     ; Check if current byte = 0
        je          .end

        ror         r12d, 13                   ; Use r12 to have qword hash, r12d - dword hash
        add         r12, rbx
        inc         r11
        jmp         .next_byte
.end:
        mov         rax, r12                   ; Return value is hash

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
        enter       %$localsize, 0

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
        enter       %$localsize, 0

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
