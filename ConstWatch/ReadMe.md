<b>Overview </b> <br>
This python script when run, will keep watching the specified directory and subdirectories for any files created. A file when created, the full file path is obtained and the following actions are taken:
- checks if the file is an executable or not and runs further checks if it is a PE executable
- using the 'pefile' python module it checks the Import Address Table (IAT) for functions that begin with "Crypt"
- using the 'signsrch' program checks the PE for crypto constants, Crypto functions, codec's or to indicate if the malware is packed

<b>Installation </b> </br>
Install the following python modules in the windows Visual Studio's 2013 distribution of Python 2.7
- pywin32 - used the win32file module's CreateFile function and the win32con modules which provides the API interface for MS_ReadDirecotryChanges
- pefile - pefile module helps with reading the contents of the IAT in a PE. Since we are interested in ransomware, regular expressions are used to output the functions that begin with Crypt (Microsoft's Cryptography functions).
- signsearch.exe - was compiled from the source code available from http://aluigi.altervista.org/mytoolz.htm. From my research, this utility is the best readily available program which is independent and can work in the Windows environment for detecting compression and encryption algorithms.
- 
<b>Usage </b> </br>
From any directory execute the python file "python createfilewatch.py"

<i>Conditions:</i>
The program has access to read the files in the directories supplied to watch.
The command window has the output of the program.
