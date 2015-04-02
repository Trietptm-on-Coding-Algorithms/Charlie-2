<b>Overview </b> <br>
This python script when run, will keep watching the specified directory and subdirectories for any files created. A file when created, the full file path is obtained and the following actions are taken:
- checks if the file is an executable or not and runs further checks if it is a PE executable
- using the 'pefile' python module it checks the Import Address Table (IAT) for functions that begin with "Crypt"
- using the 'signsrch' program checks the PE for crypto constants, Crypto functions, codec's or to indicate if the malware is packed
