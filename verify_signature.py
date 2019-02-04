#!/usr/bin/env python3
# Dump Android Verified Boot Signature (c) B.Kerler 2017-2018
import hashlib
import struct
import binascii
import rsa
import sys
import argparse
from rsa import common, transform, core
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from Library import libavb

version="v1.4"

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
        return [name,length,hash,pub_key,bytes(der[3])[1:2]]

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
    os_version=0
    name="" #BOOT_NAME_SIZE 16
    cmdline="" #BOOT_ARGS_SIZE 512
    id=[] #uint*8
    extra_cmdline="" #BOOT_EXTRA_ARGS_SIZE 1024

def getheader(inputfile):
    param = androidboot()
    with open(inputfile, 'rb') as rf:
        header = rf.read(0x660)
        fields = struct.unpack('<8sIIIIIIIIII16s512s8I1024s', header)
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
        param.os_version = fields[10]
        param.name = fields[11]
        param.cmdline = fields[12]
        param.id = [fields[13],fields[14],fields[15],fields[16],fields[17],fields[18],fields[19],fields[20]]
        param.extra_cmdline = fields[21]
    return param

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def main(argv):
    print("\nBoot Signature Tool "+version+"(c) B.Kerler 2017-2018")
    print("----------------------------------------------")
    parser = argparse.ArgumentParser(description='Boot Signature Tool (c) B.Kerler 2017-2018')
    parser.add_argument('--file','-f', dest='filename', default="", action='store', help='boot or recovery image filename')
    parser.add_argument('--length','-l', dest='inject', action='store_true', default=False, help='adapt signature length')
    args = parser.parse_args()

    if args.filename=="":
        print("Usage: verify_signature.py -f [boot.img]")
        exit(0)
    param=getheader(args.filename)
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

    with open(args.filename,'rb') as fr:
        data=fr.read(length)
        if data[-qcdtsize:-qcdtsize+4]==b"AVB0":
            signature=data[-qcdtsize:]
            data=data[0:-qcdtsize]
            avbhdr=libavb.AvbVBMetaHeader(signature[:256])
            release_string=avbhdr.release_string.replace(b"\x00",b"").decode('utf-8')
            print(f"AVB >=2.0 vbmeta detected: {release_string}")
            hashdata=signature[avbhdr.SIZE:]
            avbhash=libavb.AvbHashDescriptor(hashdata)
            print("\nImage-Target: \t" + str(avbhash.partition_name))
            # digest_size = len(hashlib.new(name=avbhash.hash_algorithm).digest())
            # digest_padding = round_to_pow2(digest_size) - digest_size
            # block_size=4096
            # (hash_level_offsets, tree_size) = libavb.calc_hash_level_offsets(avbhash.image_size, block_size, digest_size + digest_padding)
            # root_digest, hash_tree = libavb.generate_hash_tree(fr, avbhash.image_size, block_size, avbhash.hash_algorithm, avbhash.salt, digest_padding, hash_level_offsets, tree_size)

            ctx=hashlib.new(name=avbhash.hash_algorithm)
            ctx.update(avbhash.salt)
            ctx.update(data[:avbhash.image_size])
            root_digest=ctx.digest()
            print("AVB v1 detected.")
            print("\nSalt: \t\t\t" + str(binascii.hexlify(avbhash.salt).decode('utf-8')))
            print("Image-Size: \t" + hex(avbhash.image_size))
            digest=str(binascii.hexlify(root_digest).decode('utf-8'))
            hash=str(binascii.hexlify(avbhash.digest).decode('utf-8'))
            print("\nCalced Image-Hash: \t" + digest)
            #print("Calced Hash_Tree: " + str(binascii.hexlify(hash_tree)))
            print("Hash: \t\t\t\t" + hash)
            if digest==hash:
                print("AVB-Status: VERIFIED, 0")
            else:
                print("AVB-Status: RED, 3 or ORANGE, 1")

            exit(0)
        else:
            sha256 = hashlib.sha256()
            sha256.update(data)
            signature = fr.read()
            target,siglength,hash,pub_key,flag=dump_signature(signature)
            id=binascii.hexlify(data[576:576+32])
            print("ID: "+id.decode('utf-8'))
            print("\nImage-Target: "+str(target))
            print("Image-Size: "+hex(length))
            print("Signature-Size: "+hex(siglength))
            meta=b"\x30"+flag+b"\x13"+bytes(struct.pack('B',len(target)))+target+b"\x02\x04"+bytes(struct.pack(">I",length))
            print(meta)
            sha256.update(meta)
            digest=sha256.digest()
            print("\nCalced Image-Hash: "+str(binascii.hexlify(digest)))
            print("Signature-Hash: " + str(binascii.hexlify(hash)))
            if str(binascii.hexlify(digest))==str(binascii.hexlify(hash)):
                print("AVB-Status: VERIFIED, 0")
            else:
                print("AVB-Status: RED, 3 or ORANGE, 1")

            modulus=int_to_bytes(pub_key.n)
            exponent=int_to_bytes(pub_key.e)
            mod=str(binascii.hexlify(modulus).decode('utf-8'))
            print("\nSignature-RSA-Modulus (n): "+mod)
            print("Signature-RSA-Exponent (e): " + str(binascii.hexlify(exponent).decode('utf-8')))
            if mod=="eb0478815591b50e090702347db475af966f886ba5d3c1baa273851400aea7cc8481398defb7b747c33fda93512b9aefa538ea4ffc907b4836410782e57dbf7241080f5f380dd2362345fc09c3f15e122176951d07d06802fa5f2a821856dd002a8699fedad774d60be1ebc6c05e0db849375a43228c54d6c2fe28e88d530d971604ef7dc1a4e4faad79bff2e4bcc783dddcc798bbf7e0b9fc43e0d74930f8ae93d5c3f5971b0ddbcc881b9117267cdfa3d29d276fc8909440ef0cfa410a866ece65be77c551a3c838d629cebd27c7d62f38535f68484d248703c686359fa6ab3fdc6591153d79c50af6972d2b02fd3ddabef019d5da8699367ceceb853e4d3f":
                print("\n!!!! Image seems to be signed by google test keys, yay !!!!")
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
            print("\nTZ Root of trust (locked): " + str(binascii.hexlify(root_of_trust_locked)))
            print("TZ Root of trust (unlocked): " + str(binascii.hexlify(root_of_trust_unlocked)))

    if (args.inject==True):
        pos = signature.find(target)
        if (pos != -1):
            lenpos = signature.find(struct.pack(">I",length)[0],pos)
            if (lenpos!=-1):
                with open(args.filename[0:-4]+"_signed.bin",'wb') as wf:
                    wf.write(data)
                    wf.write(signature[0:lenpos])
                    wf.write(struct.pack(">I",length))
                    wf.write(signature[lenpos+4:])
                    print("Successfully injected !")

if __name__ == "__main__":
   main(sys.argv[1:])
