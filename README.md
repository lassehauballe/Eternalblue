# Eternalblue in C#

This project is an almost direct translation of https://github.com/EmpireProject/Empire/blob/master/data/module_source/exploitation/Exploit-EternalBlue.ps1. 

It was created to help me gain an understanding of how Eternalblue actually works. Please do use on your own risk, since I have also seen a couple of BSOD during development.
The code has only been tested using msfvenom x64 exec and meterpreter reverse shell shellcode. Remember this is the old eternalblue exploit, so should not work on windows 8 and newer. 

![alt text](https://raw.githubusercontent.com/povlteksttv/Eternalblue/master/img/eternalblue.PNG?raw=true)

## To use: 
1) Replace the shellcode called buf in main (not in make_kernel_shellcode!)
2) Compile as 64-bit
3) Eternalblue.exe [ip] [number of grooms]

