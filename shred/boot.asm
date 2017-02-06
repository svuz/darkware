BITS 16
start:
	; Set up 4K stack after this bootloader
	; [Remember: Effective Address = Segment*16 + Offset]
	mov ax, 07C0h   ; Set 'ax' equal to the location of this bootloader divided by 16
	add ax, 20h     ; Skip over the size of the bootloader divided by 16
	mov ss, ax      ; Set 'ss' to this location (the beginning of our stack region)
	mov sp, 4096    ; Set 'ss:sp' to the top of our 4K stack
	

	; Set data segment to where we're loaded so we can implicitly access all 64K from here
	mov ax, 07C0h   ; Set 'ax' equal to the location of this bootloader divided by 16
	mov ds, ax      ; Set 'ds' to the this location
	call clrscr
	mov si, message
	call print
	cli
	hlt
clrscr:
mov dx, 0 ; Set cursor to top left-most corner of screen
mov bh, 0
mov ah, 0x2
int 0x10
mov cx, 2000 ; print 2000 chars
mov bh, 0
mov bl, 0x204 ; green bg/blue fg
mov al, 0x00 ; blank char
mov ah, 0x9
int 0x10
ret
data:
	message  db "SIMBA COUCHI HHHH",0
print:
	mov ah, 0Eh     ; Specify 'int 10h' 'teletype output' function
	mov BL, 0x44 ; color 
	                ; [AL = Character, BH = Page Number, BL = Colour (in graphics mode)]
.printchar:
	lodsb           ; Load byte at address SI into AL, and increment SI
	cmp al, 0
	je .done        ; If the character is zero (NUL), stop writing the string
	int 10h         ; Otherwise, print the character via 'int 10h'
	jmp .printchar  ; Repeat for the next character
.done:
	ret
times 510-($-$$) db 0 
dw 0xAA55	        ; => 0x55 0xAA (little endian byte order)