
Binary entropy calculated on the (.txt, .doc, .pdf)files located within the directory(path) specified.

# HOW TO BUILD: (win)
Install Python  2.7.9 @ https://www.python.org/downloads/release/python-279/
Install MVC++ for Python 2.7 @ http://aka.ms/vcpython27
Set environmental variables or 'dir' around on cmd.exe
pip install pdfminer
pip install pyPdf
Download http://www.lfd.uci.edu/~gohlke/pythonlibs/#numpy cp27
Download http://www.lfd.uci.edu/~gohlke/pythonlibs/#scipy cp27
pip install "numpy-1.9.2+mkl-cp27-none-win32.whl"
pip install scipy-0.15.1-cp27-none-win32.whl

# HOW TO RUN:
python bintropy.py

The same script can be run in linux env:
# BUILD IN linux:
sudo apt-get install python-pdfminer (or) pip install pdfminer
pip install numpy 
pip install scipy
--change the "path" variable to linux env---"

# RUN:
python bintropy.py

Sample shot can be found here: 
http://i.imgur.com/nOVlE1Y.png

