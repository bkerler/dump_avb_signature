# Dump/Verify Android Verified Boot Signature Hash v1.5 (c) B.Kerler 2017-2019

Why
===
- For researching Android Verified Boot issues
- To exploit TZ image verification :)
  
Installation
=============
1. Get python 3.6 64-Bit
2. python -m pip install pycryptodome 

Run
===
For AVB v1:
```
python verify_signature.py --file boot.img
```

For AVB v2:
```
python verify_signature.py --file boot.img --vbmeta vbmeta.img
```

 
Published under MIT license

Enjoy !
