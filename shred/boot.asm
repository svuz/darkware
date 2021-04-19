BITS 16
start:
	
	mov ax, 07C0h   
	add ax, 20h  
	mov ss, ax 
	mov sp, 4096 
	mov ax, 07C0h 
	mov ds, ax  
	call clrscr
	mov si, message
	call print
	cli
	hlt
clrscr:
mov dx, 0 
mov bh, 0
mov ah, 0x2
int 0x10
mov cx, 2000 
mov bh, 0
mov bl, 0x204 
mov al, 0x00 
mov ah, 0x9
int 0x10
ret
data:
	message  db "SIMBA COUCHI HHHH",0
print:
	mov ah, 0Eh     
	mov BL, 0x44  
	                
.printchar:
	lodsb           
	cmp al, 0
	je .done        
	int 10h         
	jmp .printchar 
.done:
	ret
times 510-($-$$) db 0 
dw 0xAA55	        
