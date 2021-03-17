# Eternalblue in C#

This project is an almost direct translation of https://github.com/EmpireProject/Empire/blob/master/data/module_source/exploitation/Exploit-EternalBlue.ps1. However, the Empire-script did not test if the target is vulnerable. In order to test for this, I translated a piece of Metasploits auxiliary/scanner/smb/smb_ms17_010

It was created as an educational project to help myself gain an understanding of how Eternalblue actually works.  
Please do use on your own risk, since I have also seen a couple of BSOD during development.  
The code has only been tested using msfvenom x64 exec and meterpreter reverse shell shellcode. Remember this is the old eternalblue exploit, so should not work on windows 8 and newer. 

![alt text](https://github.com/povlteksttv/Eternalblue/blob/master/img/Eternalblue.PNG?raw=true)

## How to use: 
1) Replace the shellcode called buf in main (not in make_kernel_shellcode!)
2) Compile as 64-bit
3) Eternalblue.exe [ip] [number of grooms]

