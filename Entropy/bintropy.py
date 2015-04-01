#Bin entropy calculation using statistical test suite based on Discrete fourier transform of the sequence. 
#The purpose is to detect the repetetive patterns that are near to each other in the sequence which would indicate
#a deviation from the assumption of randomness.
# Malware detection by entropy - ascii entropy and binary entropy
"""
Bin Entropy calculated based on 'Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications'
published by National Institute of Standards and Technology, U.S Department of Commerce
Source : http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf
FFT - scipy.fftpack
pdfminer - PDF extraction tool
Malware detection by entropy based on 'Using Entropy analysis to find encrypted and packed malware'
published by IEEE Security and Privacy
ascii_entropy - entropy calculation on ascii contents of the file range(0 - 8)
"""

import sys, os, binascii              
import math, pdfminer
from scipy.fftpack import fft
from StringIO import StringIO
from pdfminer.pdfparser import PDFParser, PDFDocument, PDFPage, PDFSyntaxError
from pdfminer.layout import LAParams
from pdfminer.converter import TextConverter
from pdfminer.pdfinterp import PDFResourceManager,process_pdf
from pyPdf import PdfFileReader   
path = "/home/kani/Desktop/"
d = os.listdir(path)
byteArr = []
l = True
def pdf_r(fil):
    try:
        f = open(path+"/"+fil,"rb")
        mem = StringIO(f)
        parser = PDFParser(mem)#parser to the pdf
        doc = PDFDocument(parser) 
        rsrcmgr = PDFResourceManager()
        retstr = StringIO()
        device = TextConverter(rsrcmgr, retstr,codec='utf-8', laparams=LAParams()) #PDF text
        process_pdf(rsrcmgr, device, f) #extract the pdf content using pdfmanager
        device.close()
        str = retstr.getvalue()
        retstr.close()
        #byteArr = map(ord, str) #map the extracted content to ASCII codes
        con = bin(int(binascii.hexlify(str),16))
       # bintropy(con)
        f.close()
    except PDFSyntaxError:    
        print "Encrypted pdf! found in",path+"/"+fil

# calculate the ascii_frequency of each byte value in the file
# read the whole file into a byte array 'byteArr' 
def acsii_entropy(byteArr,fileSize):
    freqList = [0]*fileSize
    for b in range(256):
        ctr = 0.0
        for byte in byteArr:
            if byte == b:
                ctr += 1  
        freqList.append(float(ctr) / fileSize)
    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        if freq > 0:
            ent = ent + (freq * math.log(freq, 2))
    ent = -ent
    print 'Shannon entropy (min bits per byte-character):',ent
   # print 'Min possible file size assuming max theoretical compression efficiency:'
   # print (ent * fileSize), 'in bits' 
   # print (ent * fileSize) / 8, 'in bytes'
   
def bintropy(con): #module for bintropy calculation
    s = 0.0
    slist = []
    dict = {'1':1,'0':-1}
    for i in con[2:]:
        slist.append(dict[i]) #get the -1 and 1 sequence
        s = s + dict[i]
    dft = fft(slist)    #get the dft of the sequence
    ddft = dft[0:len(slist)/2] # half the dft - substring
    modulus = [abs(i) for i in ddft] #modulus of the substring in the dft    
    t = math.sqrt(math.log(1/0.05) * len(slist)) #95% threshold peak height   
    thoery_t = 0.95 * len(slist)/2 #expected theoretical number of peaks
    peak = 0
    for m in modulus:
        if m < t:
            peak += 1  #actual observed number of peaks
    d = (peak - thoery_t)/math.sqrt(len(slist) * 0.95 * 0.05 /4)#normalized difference between the theoretical and observed freq of peaks
    ent = math.erfc(abs(d)/math.sqrt(2))
    print "Entropy:",ent
    if ent >= 0.01:
        print "Encryption happening"
        l = False 
        #s_obs = abs(s)/math.sqrt(len(con[2:])) #test statistic of the binary content 
        #ent = math.erfc(s_obs/math.sqrt(2))
        # print path+"/"+fil,"Bin Entropy :",ent
        #if f.read(6) == "Salted":
        #   print "Salted"
        #byteArr = map(ord, f.read())
        #f.close()
        #fileSize = len(byteArr)
        #entropy(byteArr, fileSize)  
    
while True: # keep checking till encryption is detected
    root = '/home/kani/Desktop'
    for fname in d: #check each file in the directory "path"
        if fname.endswith('.pdf'): # .pdf file check
            pdf_r(fname)
        elif fname.endswith('.txt') or fname.endswith('.doc'): # if .txt or .doc file check
            f = open(path+"/"+fname,"rb") 
            con = bin(int(binascii.hexlify(f.read()),16)) #convert the binary sequence
            bintropy(con) #calculate bin entropy of the file 
        

        
