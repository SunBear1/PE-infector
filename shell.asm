.686
.model flat
extern _MessageBoxA@16: PROC
extern _ExitProcess@4: PROC
public _shellcode, _get_size, _get_adr

; 18,446,744,073,709,551,615
.data
tytul db 'TEST', 0

.code

_get_size proc

 mov  eax,offset _end_shell
 sub eax,offset poczatek
 ret
 _get_size endp

_get_adr proc

 mov  eax,offset _end_shell
 mov eax,offset poczatek
 ret
 _get_adr endp

 poczatek:
_shellcode proc

nop
pushad
call    routine

routine:
pop     ebp
sub     ebp, offset routine
push    0                               ; // MB_OK
lea     eax, [ebp + szCaption]
push    eax                          ;    // lpCaption
lea     eax, [ebp + szText]
push    eax                           ;   // lpText
push    0                             ;   // hWnd
mov     eax, 0AAAAAAAAh
call    eax                            ;  // MessageBoxA

popad
push    0AAAAAAAAh                     ;  // OEP
ret

szCaption :
db 'kocham eti',0


szText :
db 'kocham pliki PE',0
nop

_shellcode ENDP

_end_shell: nop

END