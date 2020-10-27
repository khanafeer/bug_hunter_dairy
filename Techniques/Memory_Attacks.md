# summary 

Several protection mechanisms have been designed to make EIP control more difficult to obtain or exploit.Microsoft implements several such protections, specifically *Data Execution Prevention* (DEP), Address Space Layout Randomization* (ASLR),and *Control Flow Guard* (CFG).

**DEP** is a set of hardware and software technologies that perform additional checks on memory to help prevent malicious code from running on a system. The primary benefit of DEP is to help prevent code execution from data pages by raising an exception when such attempts are made.

**ASLR** randomizes the base addresses of loaded applications and DLLs every time the operating system is booted. On older Windows operating systems like Windows XP where ASLR is not implemented, all DLLs are loaded at the same memory address every time, making exploitation much simpler. When coupled with DEP, ASLR provides a very strong mitigation against exploitation.

Finally, CFG, Microsoft’s implementation of *control-flow integrity*, performs validation of indirect code branching, preventing overwrites of function pointers.



# Windows Buffer OverFlow

```bash
$ msf-pattern_create -l 800
 
 EIP=42306142
 
$ msf-pattern_offset -l 800 -q 42306142
 [*] Exact match at offset 780
```

