        bits        64
        
        extern      puts
        extern      strlen
        extern      itoa

        extern      GetStdHandle
        extern      WriteFile
        extern      ExitProcess
        extern      StringCchCopyA

        global      WinMain


;; Save and restore volatile (preserved) registers excluding rsp, rbp
        %macro      save_regs 0
        push        rbx
        push        rdi
        push        rsi
        push        r12
        push        r13
        push        r14
        push        r15
        %endmacro  

        %macro      restore_regs 0
        pop         rbx
        pop         rdi
        pop         rsi
        pop         r12
        pop         r13
        pop         r14
        pop         r15
        %endmacro
        
        

        section     .data        
STD_OUTPUT_HANDLE:
        dq          -11

endl:
        db          10, 0

szMsg1:
        db          "msg1", 10, 0

szMsg2:
        db          "Hello, world! I love pizza.", 10, 0



        section     .bss
szBuffer:
        resb        24



        section     .text
;; void WinMain()
WinMain:
        %push       proc_context
        %stacksize  flat64
        %assign     %$localsize 0
        %local      iNum1:qword
        enter       %$localsize, 0
        save_regs  
        
        ; Init local vars
        mov         qword [iNum1], 1337
        
        ; Print num
        mov         rcx, qword [iNum1]
        call        PrintNum
        
        lea         rcx, [endl]
        call        PrintStr

        ; Print str        
        lea         rcx, [szMsg2]
        call        PrintStr
            
   
        ; Exit
        mov         rcx, 0
        call        ExitProcess

        restore_regs
        leave      
        ret        
        %pop       


;; void PrintNum (int iNum)
;; iNum = rcx
PrintNum:
        %push       proc_context
        %stacksize  flat64
        %assign     %$localsize 0
        %local      iNum:qword
        %local      szNum:byte[24]
        enter       %$localsize, 0
        save_regs
        
        ; Save argument(s) as local var(s)
        mov         qword [iNum], rcx
        
        ; Convert int to string
        mov         rcx, qword [iNum]
        lea         rdx, [szNum]
        mov         r8, 10
        call        itoa
        
        ; Print string
        lea         rcx, [szNum]
        call        PrintStr    
        
        restore_regs
        leave      
        ret        
        %pop    
        
        

;; void PrintStr (PSTR pStr)
;; pStr = rcx
PrintStr:
        %push       proc_context
        %stacksize  flat64
        %assign     %$localsize 0
        %local      pStr:qword          ; Pointer to string
        %local      cbStr:qword         ; Length of string
        %local      cbWritten:qword
        %local      hStdOut:qword
        enter       %$localsize, 0
        save_regs  

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
        mov         r9, qword [cbWritten]
        call        WriteFile

        restore_regs
        leave      
        ret        
        %pop       
