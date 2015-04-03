import os
import win32file
import win32con
import time
import tqdm
import pefile
import peutils
import re
import subprocess
import sys

ACTIONS = {
    1: "Create",
    2: "Del",
    3: "Updt",
    4: "Renamed from original",
    5: "Renamed to something"
}

FILE_LIST_DIRECTORY = 0x0001

#Considering Windows 7 using this path
path_obs = "C://Users//"
hDir = win32file.CreateFile(
    path_obs,
    FILE_LIST_DIRECTORY,
    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
    None,
    win32con.OPEN_EXISTING,
    win32con.FILE_FLAG_BACKUP_SEMANTICS,
    None
)
while 1:

    results = win32file.ReadDirectoryChangesW(
        hDir,
        1024,
        True,
        win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
        win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
        win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
        win32con.FILE_NOTIFY_CHANGE_SIZE |
        win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
        win32con.FILE_NOTIFY_CHANGE_SECURITY,
        None,
        None
    )

    for action, file in results:
        full_filename = os.path.join(path_obs, file)
        if ACTIONS.get(action) == "Create":
            print""
            print "Scanning " + full_filename + " for constants...\n"
            time.sleep(1)
            try:
                fl = open(full_filename, "rb")
            except IOError as e:
                print "I/O error({0}): {1}".format(e.errno, e.strerror)
            else:
                i=0
                if fl.read(2) == "MZ":
                    print full_filename + " is an executable"
                    pe = pefile.PE(full_filename)
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            fnname = str(imp.name)
                            if re.match('^Crypt', fnname):
                                print '\t', entry.dll, hex(imp.address), imp.name
                                i=1
                            else:
                                i=0
                                pass
                    if i==0:
                        print "No Crypt dll's found in IAT, perhaps packed or benign\n"
                        signatures = peutils.SignatureDatabase('userdb.txt')
                        matches = signatures.match_all(pe, ep_only = True)
                        print "Likely packers:\n"
                        print matches
                    print "Running Scan on " + full_filename + "for Crypto Constants...\n"
                    cmd = ['C:\Python27\signsrch\signsrch.exe', full_filename]
                    res = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    j=0
                    while True:
                        text = res.stdout.readline()
                        if not text:
                            break
                        if "offset" in text:
                            j=1
                        if j==1:
                            print text


                fl.close()


