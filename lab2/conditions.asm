        mov         rax, 1
        cmp         rax, 1
        je          .print_msg1
        cmp         rax, 2
        je          .print_msg2
        jmp         .print_msg3

.print_msg1:
        lea         rcx, [szMsg1]
        call        PrintStr
        jmp         .next
.print_msg2:
        lea         rcx, [szMsg2]
        call        PrintStr
        jmp         .next
.print_msg3:
        lea         rcx, [szMsg3]
        call        PrintStr
        jmp         .next
.next:
        mov         rcx, 0
        call        ExitProcess
