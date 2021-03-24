# Eternalblue in C#

This project is an almost direct translation of https://github.com/EmpireProject/Empire/blob/master/data/module_source/exploitation/Exploit-EternalBlue.ps1. However, the Empire-script did not test if the target is vulnerable. To test for this, I also translated a bit of Metasploits auxiliary/scanner/smb/smb_ms17_010

It was created as an educational project to help myself gain an understanding of how Eternalblue actually works.  
Please do use at your own risk, as I have also seen a couple of BSOD during development.  
The code has only been tested using msfvenom x64 exec and meterpreter reverse shell shellcode.  
Remember this is the old eternalblue exploit, so should not work on windows 8 and newer. 

## Version 2: 
* It is now hardcoded with 'Grooms' set to 12
* It can now be run using either "detect or exploit". The first will only detect if its vulnerable or not. 

![alt text](https://github.com/povlteksttv/Eternalblue/blob/master/img/Eternalblue.PNG?raw=true)

## How to use: 
1) Replace the shellcode byte[] called 'buf' in Exploit (line 623) (The current shellcode just starts notepad.exe (as system))
2) Compile
3) Eternalblue.exe [detect/exploit] [ip]
