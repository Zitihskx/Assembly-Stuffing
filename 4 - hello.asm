;mk: $mkAS && $mkGCC -pie

        global _start
        extern puts 
        extern atoi
        section .text
_start:   
        mov rbp, rsp

        mov edi, [rbp]              ; Taking argc into edi

        cmp edi, 3                  ;Compare number of arguments
        jne .error_val               ;Print error value if arguments more or less than 2 is provided


        mov rdi, [rbp+2*8]         ; Extracting first argument

        call atoi wrt ..plt         ; COnverting string to integer

        mov rcx, rax                ; First argument is the counter determining number of times the print should be done

        test rax, rax                  ; Test of argument is zero or negative
        je .end
        js .error_neg
                 
        mov rdi, [rbp+3*8]             ; Accessing second argument 

.loop1:   
        push rdi
        push rcx
        call puts wrt ..plt         ; Printing using puts 
        pop rcx
        pop rdi
        loop .loop1 
        mov rdi, 0
        jmp .end

.error_val:                          ;Displays error message for invalid parameters
        lea rdi, [rel .msg]
        call puts wrt ..plt
        mov rdi, 1
        jmp .end

.error_neg:                          ;Displays error message of negative argument supplied
        lea rdi, [rel .neg_msg]
        call puts wrt ..plt
        mov rdi, 1
.end:    
        mov rsp, rbp
        mov rax, 60
        syscall
        hlt

.msg: db "ERROR: You must supply a number and a string as arguments.", 0

.neg_msg: db "ERROR: The first argument must be a nonnegative integer.", 0