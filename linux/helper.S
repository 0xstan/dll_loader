.intel_syntax noprefix

.text
.global do_call

do_call:
#if defined(__LP64__)
    mov rsp, rdi
    push rsi
    ret
#else
    mov eax, [esp + 8]
    mov esp, [esp + 4]
    push eax
    ret
#endif

