BITS 32
global _start

section .text

_start:
	mov edx, [fs:30h]	; PEB
	mov edx, [edx +  0xc]	; PEB_LDR_DATA
	mov edx, [edx +  0xc]	; InMemOrderModuleList
next_mod:
	push edx
	mov edx, [edx + 0x18]	; dll_base
	mov eax, [edx + 0x3c] 	; get e_lfanew
	add eax, edx			; base_pe_header
	mov eax, [eax + 0x78] 	; offset data dir
	test eax, eax
	jz get_next_mod1
	add eax, edx			; EAT
	push eax
	mov ecx, [eax + 0x18] 	; EAT.NumberOfName
	mov ebx, [eax + 0x20] 	; EAT.AddressOfName
	add ebx, edx			; AdressOfName

get_next_func:
	test ecx, ecx
	jz get_next_mod
	dec ecx
	mov esi, [ebx + ecx * 4]
	add esi, edx
	mov edi, 0
	
checksum_loop:
	xor eax, eax
	lodsb ; Load byte in al
	rol edi, 7
	add edi, eax
	test al, al
	jnz checksum_loop
	cmp edi, 0x06fffe488
	jnz get_next_func
	pop eax
	mov ebx, [eax + 0x24] ; Address of name ordinals
	add ebx, edx			; RVA
	mov cx, [ebx + ecx * 2] ; Get good ordinal
	
	mov ebx, [eax + 0x1c] ; Adress of functions
	add ebx, edx			; RVA
	mov ebx, [ebx + ecx * 4] ; RVA
	add ebx, edx
	jmp $
	
get_next_mod:
	pop eax
get_next_mod1:
	pop edx
	mov edx, [edx]
	jmp next_mod
	

; LoadLibraryA 06fffe488	
section .data
address_good dd 0
