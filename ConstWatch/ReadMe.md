<b>Overview </b> <br>
This python script when run, will keep watching the specified directory and subdirectories for any files created. A file when created, the full file path is obtained and the following actions are taken:
- checks if the file is an executable or not and runs further checks if it is a PE executable
- using the 'pefile' python module it checks the Import Address Table (IAT) for functions that begin with "Crypt"
- using the 'peutils' python module and the signatures from userdb.txt the subject file is scanned for packers
- using the 'signsrch' program to check the PE for crypto constants, Crypto functions, codec's and to indicate more information about the file

<b>Installation:</b> <br>
Install the following python modules in the windows Visual Studio's 2013 distribution of Python 2.7
- pywin32 - used the win32file module's CreateFile function and the win32con modules which provides the API interface for MS_ReadDirecotryChanges
- pefile - pefile module helps with reading the contents of the IAT in a PE. Since we are interested in ransomware, regular expressions are used to output the functions that begin with Crypt (Microsoft's Cryptography functions).
<<<<<<< HEAD
- signsearch.exe - was compiled from the source code available from http://aluigi.altervista.org/mytoolz.htm. From my research, this utility is the best readily available program which is independent of any tools and can work in the Windows environment for detecting compression and encryption algorithms. Be sure to move it into the right location of C:\Python27
- pip install tqdm
=======
- signsearch.exe - was compiled from the source code available from http://aluigi.altervista.org/mytoolz.htm. From my research, this utility is the best readily available program which is independent of any tools and can work in the Windows environment for detecting compression and encryption algorithms.
- userdb.txt is a signature file obtained to support the peutils packer detection available from https://code.google.com/p/reverse-engineering-scripts/downloads/detail?name=UserDB.TXT
>>>>>>> a425b2448751bb3e3a6e064fd995e95fa2070e0e

<b>Usage </b> <br>
From any directory execute the python file "python createfilewatch.py"

<i>Conditions:-</i>
The user running the script has access to read the files in the directories supplied to watch.
The command window has the output of the script.

<b> Here it is at work </b> <br>
![ScreenShot](http://i.imgur.com/9eW8oGF.png)
