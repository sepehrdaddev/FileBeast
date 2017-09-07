import os
from Crypto import Random

chunksize = 64 * 1024


def encrypt(key, infilepath, outfilepath, method):
    filesize = str(os.path.getsize(infilepath)).zfill(16)
    if method == 'AES':
        from Crypto.Cipher import AES
        from Crypto.Hash import SHA256
        IV = Random.new().read(AES.block_size)
        key = SHA256.new(key.encode('utf-8')).digest()
        encryptor = AES.new(key, AES.MODE_CBC, IV)
    elif method == 'DES3':
        from Crypto.Cipher import DES3
        from Crypto.Hash import MD5
        IV = Random.new().read(DES3.block_size)
        key = MD5.new(key.encode('utf-8')).digest()
        encryptor = DES3.new(key, DES3.MODE_CBC, IV)
    elif method == 'BLOWFISH':
        from Crypto.Cipher import Blowfish
        from Crypto.Hash import SHA256
        IV = Random.new().read(Blowfish.block_size)
        key = SHA256.new(key.encode('utf-8')).digest()
        encryptor = Blowfish.new(key, Blowfish.MODE_CBC, IV)
    with open(infilepath, 'rb') as infile:
        with open(outfilepath, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))
                outfile.write(encryptor.encrypt(chunk))


def decrypt(key, infilepath, outfilepath, method):
    with open(infilepath, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)
        if method == 'AES':
            from Crypto.Cipher import AES
            from Crypto.Hash import SHA256
            key = SHA256.new(key.encode('utf-8')).digest()
            decryptor = AES.new(key, AES.MODE_CBC, IV)
        elif method == 'DES3':
            from Crypto.Cipher import DES3
            from Crypto.Hash import MD5
            key = MD5.new(key.encode('utf-8')).digest()
            decryptor = DES3.new(key, DES3.MODE_CBC, IV)
        elif method == 'BLOWFISH':
            from Crypto.Cipher import Blowfish
            from Crypto.Hash import SHA256
            key = SHA256.new(key.encode('utf-8')).digest()
            decryptor = Blowfish.new(key, Blowfish.MODE_CBC, IV)
        with open(outfilepath, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)
