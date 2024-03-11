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



        section     .data
STD_OUTPUT_HANDLE:
        dq          -11

endl:
        db          10, 0

szPause:
        db          "pause", 0

szMsg1:
        db          "msg1", 10, 0

szMsg2:
        db          "msg2", 10, 0
        
szMsg3:
        db          "msg3", 10, 0

szWinExec:
        db          "WinExec", 0                        ; kernel32.dll
        ;db          "CsrAllocateCaptureBuffer", 0       ; ntdll.dll

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
        
        %local      pKernel32:qword
        
        %local      iBase:qword
        %local      cNames:qword
        %local      pFunctions:qword
        %local      pNames:qword
        %local      pNameOrdinals:qword
        
        %local      pName:qword
        %local      idxName:qword
        %local      iOrdinal:qword
        %local      pWinExec:qword
        enter       %$localsize, 0
        

        ; kernel32.dll base
        mov         rbx, [gs:0x60]             ; PEB
        mov         rbx, [rbx + 0x18]          ; LDR
        mov         rbx, [rbx + 0x20]          ; InMemoryOrderModuleList (1st entry)
        mov         rbx, [rbx]                 ; 2 ntdll.dll
        mov         rbx, [rbx]                 ; 3 kernel32.dll
        mov         rbx, [rbx + 0x20]          ; InInitializationOrderLinks (1st entry)
        mov         qword [pKernel32], rbx     ; kernel32.dll base address

        mov         rcx, qword [pKernel32]
        mov         rdx, 16
        call        PrintNum
        
        
        ; kernel32.dll functions
        mov         r10, qword [pKernel32]      ; kernel32.dll base (DOS header)
        mov         ebx, [r10 + 0x3c]           ; NT header offset
        add         rbx, r10                    ; NT header
        mov         ebx, [rbx + 0x18 + 0x70]    ; Export Directory RVA
        add         rbx, r10                    ; Export Directory
        
        mov         ecx, [rbx + 0x10]           ; Base (ordinals of functions start from 1)
        mov         qword [iBase], rcx
        
        mov         ecx, [rbx + 0x14]           ; NumberOfFNames
        mov         qword [cNames], rcx
        
        mov         ecx, [rbx + 0x1c]           ; AddressOfFunctions RVA
        add         rcx, r10                    ; AddressOfFunctions
        mov         qword [pFunctions], rcx
        
        mov         ecx, [rbx + 0x20]           ; AddressOfNames RVA
        add         rcx, r10                    ; AddressOfNames
        mov         qword [pNames], rcx
        
        mov         ecx, [rbx + 0x24]           ; AddressOfNameOrdinals RVA
        add         rcx, r10                    ; AddressOfNameOrdinals
        mov         qword [pNameOrdinals], rcx
        
        
        ; EXP AREA
        lea         rcx, [task]
        call        PrintStr
        
        
        ; Find name index
        mov         rcx, qword [pNames]
        mov         rdx, 16
        call        PrintNum
                              
        mov         r12, 0
.loop:
        mov         r10, qword [pNames]
        mov         ebx, [r10 + 4 * r12]             
        add         rbx, qword [pKernel32]
        mov         qword [pName], rbx
        mov         qword [idxName], r12
                
        mov         rcx, qword [pName]
        mov         rdx, szWinExec
        call        strcmp        
        cmp         rax, 0
        je          .next
        
        inc         r12     
        cmp         r12, qword [cNames] ; Max num of iterations
        jne         .loop
        
.next:          
        mov         rcx, qword [idxName]
        mov         rdx, 16
        call        PrintNum
        
        
        ; Find ordinal
        mov         rcx, qword [pNameOrdinals]
        mov         rdx, 16
        call        PrintNum
        
        mov         rbx, qword [pNameOrdinals]
        mov         r10, qword [idxName]
        mov         ax, [rbx + 2 * r10]
        add         rax, qword [iBase]
        mov         qword [iOrdinal], rax
        
        mov         rcx, qword [iOrdinal]
        mov         rdx, 16
        call        PrintNum
        
        
        ; Find address
        mov         rcx, qword [pFunctions]
        mov         rdx, 16
        call        PrintNum
        
        mov         rbx, qword [pFunctions]
        mov         r10, qword [iOrdinal]
        sub         r10, qword [iBase]
        mov         eax, [rbx + 4 * r10]
        
        add         rax, qword [pKernel32]
        mov         qword [pWinExec], rax
        
        mov         rcx, qword [pWinExec]
        mov         rdx, 16
        call        PrintNum
        
        
        ; Call
        mov         r10, qword [pWinExec]
        lea         rcx, [szCalc]
        mov         rdx, 5
        call        r10
        
        
        ; Exit
        lea         rcx, [szPause]
        call        system
        mov         rcx, 0
        call        ExitProcess
        
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
        mov         qword [rsp+32], 0           ; 5th arg. 6th arg should be passed with [rsp+40]
        call        WriteFile

        leave
        restore_regs
        ret        
        %pop
