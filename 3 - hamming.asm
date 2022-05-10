; mk: $mkAS && $mkLD

        global hamming
        section .text

hamming:
        mov rax, rdi

        mov rbx, 32

        xor rcx, rcx 

        loop_start:
                shr rax, 1
                adc rcx, 0

                dec rbx

                jz end

                jmp loop_start
        end: 

        mov rax,rcx
        ret
