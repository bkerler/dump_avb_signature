# Dump/Verify Android Verified Boot Signature Hash v1.3 (c) B.Kerler 2017-2018

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
- python verify_signature.py --file boot.img

Issues
======
- Might not work with AVB Version 2.0 or higher
 
Published under MIT license

Enjoy !