.686
.model flat
extern _MessageBoxA@16: PROC
extern _ExitProcess@4: PROC
public _shellcode

; 18,446,744,073,709,551,615
.data
tytul db 'TEST', 0

.code
_shellcode proc
nop
pushad
nop
nop
nop
nop
nop
;call    routine

;routine :
pop     ebp
nop
nop
sub     ebp, offset routine
push    0                                // MB_OK
lea     eax, [ebp + szCaption]
push    eax                              // lpCaption
lea     eax, [ebp + szText]
push    eax                              // lpText
push    0                                // hWnd
mov     eax, 0xAAAAAAAA
call    eax                              // MessageBoxA

popad
push    0xAAAAAAAA                       // OEP
ret

szCaption :
db('d') db('T') db('m') db(' ') db('W') db('u') db('Z') db(' ')
db('h') db('3') db('r') db('e') db(0)


szText :
db('H') db('a') db('X') db('X') db('0') db('r') db('3') db('d')
db(' ') db('b') db('y') db(' ') db('d') db('T') db('m') db(0)
nop

_shellcode ENDP

END