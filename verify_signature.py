# Dump Android Verified Boot Signature (c) B.Kerler 2017
import hashlib
import struct
import binascii
import rsa
import sys
from rsa import common, transform, core
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA

def extract_hash(pub_key,data):
    hashlen = 32 #SHA256
    keylen = common.byte_size(pub_key.n)
    encrypted = transform.bytes2int(data)
    decrypted = transform.int2bytes(core.decrypt_int(encrypted, pub_key.e, pub_key.n),keylen)
    hash = decrypted[-hashlen:]
    if (decrypted[0:2] != b'\x00\x01') or (len(hash) != hashlen):
        raise Exception('Signature error')
    return hash

def dump_signature(data):
    #print (binascii.hexlify(data[0:10]))
    if data[0:2] == b'\x30\x82':
        slen = struct.unpack('>H', data[2:4])[0]
        total = slen + 4
        cert = struct.unpack('<%ds' % total, data[0:total])[0]

        der = DerSequence()
        der.decode(cert)
        cert0 = DerSequence()
        cert0.decode(bytes(der[1]))

        pk = DerSequence()
        pk.decode(bytes(cert0[0]))
        subjectPublicKeyInfo = pk[6]

        meta = DerSequence().decode(bytes(der[3]))
        name = meta[0][2:]
        length = meta[1]

        signature = bytes(der[4])[4:0x104]
        pub_key = RSA.importKey(subjectPublicKeyInfo)
        pub_key = rsa.PublicKey(int(pub_key.n), int(pub_key.e))
        hash=extract_hash(pub_key,signature)
        return [name,length,hash,pub_key]

class androidboot:
    magic="ANDROID!" #BOOT_MAGIC_SIZE 8
    kernel_size=0
    kernel_addr=0
    ramdisk_size=0
    ramdisk_addr=0
    second_addr=0
    second_size=0
    tags_addr=0
    page_size=0
    qcdt_size=0
    qcdt_addr=0
    os_version=0
    name="" #BOOT_NAME_SIZE 16
    cmdline="" #BOOT_ARGS_SIZE 512
    id=[] #uint*8
    extra_cmdline="" #BOOT_EXTRA_ARGS_SIZE 1024

def getheader(inputfile):
    param = androidboot()
    with open(inputfile, 'rb') as rf:
        header = rf.read(0x660)
        fields = struct.unpack('<8sIIIIIIIIIIII8s512s8I1024s', header)
        param.magic = fields[0]
        param.kernel_size = fields[1]
        param.kernel_addr = fields[2]
        param.ramdisk_size = fields[3]
        param.ramdisk_addr = fields[4]
        param.second_size = fields[5]
        param.second_addr = fields[6]
        param.tags_addr = fields[7]
        param.page_size = fields[8]
        param.qcdt_size = fields[9]
        param.qcdt_addr = fields[10]
        param.os_version = fields[11]
        param.name = fields[12]
        param.cmdline = fields[13]
        param.id = [fields[14],fields[15],fields[16],fields[17],fields[18],fields[19],fields[20],fields[21]]
        param.extra_cmdline = fields[22]
    return param

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def main(argv):
    print("\nDump Android Verified Boot Signature (c) B.Kerler 2017")
    print("------------------------------------------------------")
    if (len(argv)!=1):
        print("Usage: verify_signature.py [boot.img]")
        exit(0)
    filename=argv[0]
    param=getheader(filename)
    kernelsize = int((param.kernel_size + param.page_size - 1) / param.page_size) * param.page_size
    ramdisksize = int((param.ramdisk_size + param.page_size - 1) / param.page_size) * param.page_size
    secondsize = int((param.second_size + param.page_size - 1) / param.page_size) * param.page_size
    qcdtsize = int((param.qcdt_size + param.page_size - 1) / param.page_size) * param.page_size

    print("Kernel=0x%08X, length=0x%08X" % (param.page_size, kernelsize))
    print("Ramdisk=0x%08X, length=0x%08X" % ((param.page_size+kernelsize),ramdisksize))
    print("Second=0x%08X, length=0x%08X" % ((param.page_size+kernelsize+ramdisksize),secondsize))
    print("QCDT=0x%08X, length=0x%08X" % ((param.page_size+kernelsize+ramdisksize+secondsize),qcdtsize))
    length=param.page_size+kernelsize+ramdisksize+secondsize+qcdtsize
    print("Signature start=0x%08X" % length)
    sha256=hashlib.sha256()
    with open(filename,'rb') as fr:
        data=fr.read(length)
        sha256.update(data)
        signature = fr.read()
        metadata=dump_signature(signature)
        target = metadata[0]
        print("\nImage-Target: "+str(target))
        print("Image-Length: "+hex(metadata[1]))

        meta=b"\x30\x11\x13"+bytes(struct.pack('B',len(target)))+target+b"\x02\x04"+bytes(struct.pack(">I",length))
        sha256.update(meta)
        digest=sha256.digest()
        print("\nImage-Hash: "+str(binascii.hexlify(digest)))
        print("Signature-Hash: " + str(binascii.hexlify(metadata[2])))

        pub_key=metadata[3]
        modulus=int_to_bytes(pub_key.n)
        exponent=int_to_bytes(pub_key.e)
        print("\nSignature-RSA-Modulus (n): "+str(binascii.hexlify(modulus)))
        print("Signature-RSA-Exponent (e): " + str(binascii.hexlify(exponent)))

        sha256 = hashlib.sha256()
        sha256.update(modulus+exponent)
        pubkey_hash=sha256.digest()

        locked=pubkey_hash+struct.pack('<I',0x0)
        unlocked = pubkey_hash + struct.pack('<I', 0x1)
        sha256 = hashlib.sha256()
        sha256.update(locked)
        root_of_trust_locked=sha256.digest()
        sha256 = hashlib.sha256()
        sha256.update(unlocked)
        root_of_trust_unlocked=sha256.digest()
        print("\nTZ Root of trust (locked): "+str(binascii.hexlify(root_of_trust_locked)))
        print("TZ Root of trust (unlocked): " + str(binascii.hexlify(root_of_trust_unlocked)))

if __name__ == "__main__":
   main(sys.argv[1:])
