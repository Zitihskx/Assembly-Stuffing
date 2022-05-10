; mk: $mkAS && $mkLD

        global _start
        section .text

; Keep the line below (but you can change the value.)
; The automatic checker will look for it.
%define input 0x21a436fe

_start:
        mov rax, input

        mov rbx, 32

        xor rcx, rcx 

        loop_start:
                shr rax, 1
                adc rcx, 0

                dec rbx

                jz end

                jmp loop_start

        ; Compute the Hamming weight for the number
        ; in rax.
        end: 
        ; Make sure the weight is in register rdi.
                mov rdi, rcx

                mov rax, 60
                syscall
                hlt
