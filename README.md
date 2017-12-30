# Dump/Verify Android Verified Boot Signature Hash

Why
===
- For researching Android Verified Boot issues
- To exploit TZ image verification :)
  
Installation
=============
1. Get python 3.6 64-Bit
2. python -m pip install pycryptodome rsa 

Run
===
- python verify_signature.py boot.img

Issues
======
- Might not work with AVB Version 2.0 or higher
 
Published under MIT license

Enjoy !