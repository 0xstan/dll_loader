BITS 64
global _start

section .text

_start:
	mov rdx, [gs:60h]	; PEB
	mov rdx, [rdx +  0x18]	; PEB_LDR_DATA
	mov rdx, [rdx +  0x10]	; InMemOrderModuleList
next_mod:
	push rdx
	mov rdx, [rdx + 0x30]	; dll_base
	mov eax, [rdx + 0x3c] 	; get e_lfanew
	add rax, rdx			; base_pe_header
	mov eax, [rax + 0x88] 	; offset data dir
	test rax, rax
	jz get_next_mod1
	add rax, rdx			; EAT
	push rax
	mov ecx, [rax + 0x18] 	; EAT.NumberOfName
	mov ebx, [rax + 0x20] 	; EAT.AddressOfName
	add rbx, rdx			; AdressOfName

get_next_func:
	test rcx, rcx
	jz get_next_mod
	dec rcx
	mov esi, [rbx + rcx * 4]
	add rsi, rdx
	mov edi, 0
	
checksum_loop:
	xor rax, rax
	lodsb ; Load byte in al
	ror edi, 13
	add edi, eax
	test al, al
	jnz checksum_loop
	cmp edi, 0x74776072
	jnz get_next_func
	pop rax
	mov ebx, [rax + 0x24] ; Address of name ordinals
	add rbx, rdx			; RVA
	mov cx, [rbx + rcx * 2] ; Get good ordinal
	
	mov ebx, [rax + 0x1c] ; Adress of functions
	add rbx, rdx			; RVA
	mov ebx, [rbx + rcx * 4] ; RVA
	add rbx, rdx
	jmp $
	
get_next_mod:
	pop rax
get_next_mod1:
	pop rdx
	mov rdx, [rdx]
	jmp next_mod
	

; LoadLibraryA 06fffe488	
section .data
address_good dd 0
