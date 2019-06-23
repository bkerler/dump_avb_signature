#!/usr/bin/env python3
# Dump Android Verified Boot Signature (c) B.Kerler 2017-2018
import hashlib
import struct
from binascii import hexlify,unhexlify
import sys
import argparse
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from Library.libavb import *

version="v1.6"

def extract_hash(pub_key,data):
    hashlen = 32 #SHA256
    encrypted = int(hexlify(data),16)
    decrypted = hex(pow(encrypted, pub_key.e, pub_key.n))[2:]
    if len(decrypted)%2!=0:
        decrypted="0"+decrypted
    decrypted=unhexlify(decrypted)
    hash = decrypted[-hashlen:]
    if (decrypted[-0x21:-0x20] != b'\x20') or (len(hash) != hashlen):
        raise Exception('Signature error')
    return hash

def dump_signature(data):
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

def rotstate(state):
    if state==0:
        print("AVB-Status: VERIFIED, 0")
    else:
        print("AVB-Status: RED, 3 or ORANGE, 1")


def main(argv):
    info="Boot Signature Tool "+version+" (c) B.Kerler 2017-2019"
    print("\n"+info)
    print("----------------------------------------------")
    parser = argparse.ArgumentParser(description=info)
    parser.add_argument('--file','-f', dest='filename', default="", action='store', help='boot or recovery image filename')
    parser.add_argument('--vbmeta','-v', dest='vbmetaname', action='store', default='', help='vbmeta partition')
    parser.add_argument('--length', '-l', dest='inject', action='store_true', default=False, help='adapt signature length')
    args = parser.parse_args()

    if args.filename=="":
        print("Usage: verify_signature.py -f [boot.img]")
        exit(0)
    param=getheader(args.filename)
    kernelsize = int((param.kernel_size + param.page_size - 1) / param.page_size) * param.page_size
    ramdisksize = int((param.ramdisk_size + param.page_size - 1) / param.page_size) * param.page_size
    secondsize = int((param.second_size + param.page_size - 1) / param.page_size) * param.page_size
    qcdtsize = int((param.qcdt_size + param.page_size - 1) / param.page_size) * param.page_size
    
    print("Kernel=0x%08X,\tlength=0x%08X" % (param.page_size, kernelsize))
    print("Ramdisk=0x%08X,\tlength=0x%08X" % ((param.page_size+kernelsize),ramdisksize))
    print("Second=0x%08X,\tlength=0x%08X" % ((param.page_size+kernelsize+ramdisksize),secondsize))
    print("QCDT=0x%08X,\tlength=0x%08X" % ((param.page_size+kernelsize+ramdisksize+secondsize),qcdtsize))
    length=param.page_size+kernelsize+ramdisksize+secondsize+qcdtsize
    print("Signature start=0x%08X" % length)

    with open(args.filename,'rb') as fr:
        data=fr.read()
        filesize=os.stat(args.filename).st_size
        footerpos=(filesize//0x1000*0x1000)-AvbFooter.SIZE
        if data[footerpos:footerpos+4]==b"AVBf":
            ftr=AvbFooter(data[footerpos:footerpos+AvbFooter.SIZE])
            signature=data[ftr.vbmeta_offset:]
            data=data[0:ftr.vbmeta_offset]
            avbhdr=AvbVBMetaHeader(signature[:AvbVBMetaHeader.SIZE])
            release_string=avbhdr.release_string.replace(b"\x00",b"").decode('utf-8')
            print(f"\nAVB >=2.0 vbmeta detected: {release_string}\n----------------------------------------")
            if " 1.0" not in release_string and " 1.1" not in release_string:
                print("Sorry, only avb version <=1.1 is currently implemented")
                exit(0)
            hashdata=signature[avbhdr.SIZE:]
            imgavbhash=AvbHashDescriptor(hashdata)
            print("Image-Target: \t\t\t\t" + str(imgavbhash.partition_name))
            # digest_size = len(hashlib.new(name=avbhash.hash_algorithm).digest())
            # digest_padding = round_to_pow2(digest_size) - digest_size
            # block_size=4096
            # (hash_level_offsets, tree_size) = calc_hash_level_offsets(avbhash.image_size, block_size, digest_size + digest_padding)
            # root_digest, hash_tree = generate_hash_tree(fr, avbhash.image_size, block_size, avbhash.hash_algorithm, avbhash.salt, digest_padding, hash_level_offsets, tree_size)

            ctx=hashlib.new(name=imgavbhash.hash_algorithm)
            ctx.update(imgavbhash.salt)
            ctx.update(data[:imgavbhash.image_size])
            root_digest=ctx.digest()
            print("Salt: \t\t\t\t\t" + str(hexlify(imgavbhash.salt).decode('utf-8')))
            print("Image-Size: \t\t\t\t" + hex(imgavbhash.image_size))
            img_digest=str(hexlify(root_digest).decode('utf-8'))
            img_avb_digest=str(hexlify(imgavbhash.digest).decode('utf-8'))
            print("\nCalced Image-Hash: \t\t\t" + img_digest)
            #print("Calced Hash_Tree: " + str(binascii.hexlify(hash_tree)))
            print("Image-Hash: \t\t\t\t" + img_avb_digest)
            avbmetacontent={}
            vbmeta=None
            if args.vbmetaname=="":
                if os.path.exists("vbmeta.img"):
                    args.vbmetaname="vbmeta.img"
            if args.vbmetaname!="":
                with open(args.vbmetaname,'rb') as vbm:
                    vbmeta=vbm.read()
                    avbhdr=AvbVBMetaHeader(vbmeta[:AvbVBMetaHeader.SIZE])
                    if avbhdr.magic!=b'AVB0':
                        print("Unknown vbmeta data")
                        exit(0)
                    class authentication_data(object):
                        def __init__(self,hdr,data):
                            self.hash=data[0x100+hdr.hash_offset:0x100+hdr.hash_offset+hdr.hash_size]
                            self.signature=data[0x100+hdr.signature_offset:0x100+hdr.signature_offset+hdr.signature_size]

                    class auxilary_data(object):
                        def __init__(self, hdr, data):
                            self.data=data[0x100+hdr.authentication_data_block_size:0x100+hdr.authentication_data_block_size+hdr.auxiliary_data_block_size]

                    authdata=authentication_data(avbhdr,vbmeta)
                    auxdata=auxilary_data(avbhdr,vbmeta).data

                    auxlen=len(auxdata)
                    i=0
                    while (i<auxlen):
                        desc=AvbDescriptor(auxdata[i:])
                        data=auxdata[i:]
                        if desc.tag==AvbPropertyDescriptor.TAG:
                            avbproperty=AvbPropertyDescriptor(data)
                            avbmetacontent["property"]=dict(avbproperty=avbproperty)
                        elif desc.tag==AvbHashtreeDescriptor.TAG:
                            avbhashtree=AvbHashtreeDescriptor(data)
                            partition_name=avbhashtree.partition_name
                            salt=avbhashtree.salt
                            root_digest=avbhashtree.root_digest
                            avbmetacontent[partition_name]=dict(salt=salt,root_digest=root_digest)
                        elif desc.tag==AvbHashDescriptor.TAG:
                            avbhash=AvbHashDescriptor(data)
                            partition_name=avbhash.partition_name
                            salt=avbhash.salt
                            digest=avbhash.digest
                            avbmetacontent[partition_name] = dict(salt=salt,digest=digest)
                        elif desc.tag==AvbKernelCmdlineDescriptor.TAG:
                            avbcmdline=AvbKernelCmdlineDescriptor(data)
                            kernel_cmdline=avbcmdline.kernel_cmdline
                            avbmetacontent["cmdline"] = dict(kernel_cmdline=kernel_cmdline)
                        elif desc.tag==AvbChainPartitionDescriptor.TAG:
                            avbchainpartition=AvbChainPartitionDescriptor(data)
                            partition_name=avbchainpartition.partition_name
                            public_key=avbchainpartition.public_key
                            avbmetacontent[partition_name] = dict(public_key=public_key)
                        i += desc.SIZE+len(desc.data)

            vbmeta_digest=None
            if imgavbhash.partition_name in avbmetacontent:
                if "digest" in avbmetacontent[imgavbhash.partition_name]:
                    digest=avbmetacontent[imgavbhash.partition_name]["digest"]
                    vbmeta_digest = str(hexlify(digest).decode('utf-8'))
                    print("VBMeta-Image-Hash: \t\t\t" + vbmeta_digest)
            else:
                print("Couldn't find "+imgavbhash.partition_name+" in "+args.vbmetaname)
                exit(0)

            if vbmeta!=None:
                pubkeydata=vbmeta[AvbVBMetaHeader.SIZE+avbhdr.authentication_data_block_size+avbhdr.public_key_offset:
                                  AvbVBMetaHeader.SIZE+avbhdr.authentication_data_block_size+avbhdr.public_key_offset
                                  +avbhdr.public_key_size]
                modlen = struct.unpack(">I",pubkeydata[:4])[0]//4
                n0inv = struct.unpack(">I", pubkeydata[4:8])[0]
                modulus=hexlify(pubkeydata[8:8+modlen]).decode('utf-8')
                print("\nSignature-RSA-Modulus (n):\t"+modulus)
                print("Signature-n0inv: \t\t\t" + str(n0inv))
                if modulus=="d804afe3d3846c7e0d893dc28cd31255e962c9f10f5ecc1672ab447c2c654a94b5162b00bb06ef1307534cf964b9287a1b849888d867a423f9a74bdc4a0ff73a18ae54a815feb0adac35da3bad27bcafe8d32f3734d6512b6c5a27d79606af6bb880cafa30b4b185b34daaaac316341ab8e7c7faf90977ab9793eb44aecf20bcf08011db230c4771b96dd67b604787165693b7c22a9ab04c010c30d89387f0ed6e8bbe305bf6a6afdd807c455e8f91935e44feb88207ee79cabf31736258e3cdc4bcc2111da14abffe277da1f635a35ecadc572f3ef0c95d866af8af66a7edcdb8eda15fba9b851ad509ae944e3bcfcb5cc97980f7cca64aa86ad8d33111f9f602632a1a2dd11a661b1641bdbdf74dc04ae527495f7f58e3272de5c9660e52381638fb16eb533fe6fde9a25e2559d87945ff034c26a2005a8ec251a115f97bf45c819b184735d82d05e9ad0f357415a38e8bcc27da7c5de4fa04d3050bba3ab249452f47c70d413f97804d3fc1b5bb705fa737af482212452ef50f8792e28401f9120f141524ce8999eeb9c417707015eabec66c1f62b3f42d1687fb561e45abae32e45e91ed53665ebdedade612390d83c9e86b6c2da5eec45a66ae8c97d70d6c49c7f5c492318b09ee33daa937b64918f80e6045c83391ef205710be782d8326d6ca61f92fe0bf0530525a121c00a75dcc7c2ec5958ba33bf0432e5edd00db0db33799a9cd9cb743f7354421c28271ab8daab44111ec1e8dfc1482924e836a0a6b355e5de95ccc8cde39d14a5b5f63a964e00acb0bb85a7cc30be6befe8b0f7d348e026674016cca76ac7c67082f3f1aa62c60b3ffda8db8120c007fcc50a15c64a1e25f3265c99cbed60a13873c2a45470cca4282fa8965e789b48ff71ee623a5d059377992d7ce3dfde3a10bcf6c85a065f35cc64a635f6e3a3a2a8b6ab62fbbf8b24b62bc1a912566e369ca60490bf68abe3e7653c27aa8041775f1f303621b85b2b0ef8015b6d44edf71acdb2a04d4b421ba655657e8fa84a27d130eafd79a582aa381848d09a06ac1bbd9f586acbd756109e68c3d77b2ed3020e4001d97e8bfc7001b21b116e741672eec38bce51bb4062331711c49cd764a76368da3898b4a7af487c8150f3739f66d8019ef5ca866ce1b167921dfd73130c421dd345bd21a2b3e5df7eaca058eb7cb492ea0e3f4a74819109c04a7f42874c86f63202b462426191dd12c316d5a29a206a6b241cc0a27960996ac476578685198d6d8a62da0cfece274f282e397d97ed4f80b70433db17b9780d6cbd719bc630bfd4d88fe67acb8cc50b768b35bd61e25fc5f3c8db1337cb349013f71550e51ba6126faeae5b5e8aacfcd969fd6c15f5391ad05de20e751da5b9567edf4ee426570130b70141cc9e019ca5ff51d704b6c0674ecb52e77e174a1a399a0859ef1acd87e":
                    print("\n!!!! Image seems to be signed by google test keys, yay !!!!")
            else:
                print("VBMeta info missing... please copy vbmeta.img to the directory.")
            state=3
            if img_digest==img_avb_digest:
                state=0
                if vbmeta_digest!=None:
                    if vbmeta_digest==img_digest:
                        state=0
                    else:
                        state=3
            rotstate(state)

            exit(0)
        else:
            signature=data[length:]
            data=data[:length]
            sha256 = hashlib.sha256()
            sha256.update(data)
            try:
                target,siglength,hash,pub_key,flag=dump_signature(signature)
            except:
                print("No signature found :/")
                exit(0)
            id=hexlify(data[576:576+32])
            print("\nID: "+id.decode('utf-8'))
            print("Image-Target: "+str(target))
            print("Image-Size: "+hex(length))
            print("Signature-Size: "+hex(siglength))
            meta=b"\x30"+flag+b"\x13"+bytes(struct.pack('B',len(target)))+target+b"\x02\x04"+bytes(struct.pack(">I",length))
            #print(meta)
            sha256.update(meta)
            digest=sha256.digest()
            print("\nCalced Image-Hash:\t"+hexlify(digest).decode('utf8'))
            print("Signature-Hash:\t\t" + hexlify(hash).decode('utf8'))
            if str(hexlify(digest))==str(hexlify(hash)):
                rotstate(0)
            else:
                rotstate(3)
            modulus=int_to_bytes(pub_key.n)
            exponent=int_to_bytes(pub_key.e)
            mod=str(hexlify(modulus).decode('utf-8'))
            print("\nSignature-RSA-Modulus (n):\t"+mod)
            print("Signature-RSA-Exponent (e):\t" + str(hexlify(exponent).decode('utf-8')))
            if mod=="e8eb784d2f4d54917a7bb33bdbe76967e4d1e43361a6f482aa62eb10338ba7660feba0a0428999b3e2b84e43c1fdb58ac67dba1514bb4750338e9d2b8a1c2b1311adc9e61b1c9d167ea87ecdce0c93173a4bf680a5cbfc575b10f7436f1cddbbccf7ca4f96ebbb9d33f7d6ed66da4370ced249eefa2cca6a4ff74f8d5ce6ea17990f3550db40cd11b319c84d5573265ae4c63a483a53ed08d9377b2bccaf50c5a10163cfa4a2ed547f6b00be53ce360d47dda2cdd29ccf702346c2370938eda62540046797d13723452b9907b2bd10ae7a1d5f8e14d4ba23534f8dd0fb1484a1c8696aa997543a40146586a76e981e4f937b40beaebaa706a684ce91a96eea49":
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
            print("\nTZ Root of trust (locked):\t\t" + str(hexlify(root_of_trust_locked).decode('utf-8')))
            print("TZ Root of trust (unlocked):\t" + str(hexlify(root_of_trust_unlocked).decode('utf-8')))

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
