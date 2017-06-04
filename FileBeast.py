#!/usr/bin/python
##############################################################################
#                                                                            #
#                               By Sepehrdad Sh                              #
#                                                                            #
##############################################################################


import os
import os.path
import sys
import random
import getopt
import bz2
import gzip
import zlib
import tarfile
import time
import base64
import getpass
import hashlib
import requests
import subprocess
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Hash import SHA256
from Crypto.Hash import MD5
from Crypto.Cipher import _Blowfish
from struct import pack
from colorama import *
from shutil import copyfileobj
from threading import Thread


class FileBeast:
    __version__ = '1.3.1'
    enc = ['AES', 'DES3', 'BLOWFISH']
    cmp = ['BZIP', 'GZIP', 'ZLIB']
    arc = ['TAR-GZIP', 'TAR-BZIP', 'TAR']
    rm = False
    urls = {'version': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/version',
            'win32': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Windows/FileBeast.exe',
            'linux': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Linux/FileBeast'}
    checksums = {'win32': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Windows/checksum',
                 'linux': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Linux/checksum'}

    class Compress:
        def __init__(self):
            pass

        @staticmethod
        def bzip(InFilePath, OutFilePath, Level):
            try:
                with open(InFilePath, 'rb') as Input:
                    with bz2.BZ2File(OutFilePath, 'wb', Level) as Output:
                        copyfileobj(Input, Output)
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def gzip(InFilePath, OutFilePath, Level):
            try:
                with open(InFilePath, 'rb') as Input:
                    with gzip.GzipFile(OutFilePath, 'wb', Level) as Output:
                        copyfileobj(Input, Output)
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def zlib(InFilePath, OutFilePath, Level):
            try:
                compressor = zlib.compressobj(Level)
                Input = file(InFilePath, 'r')
                Output = file(OutFilePath, 'w')
                block = Input.read(2048)
                while block:
                    cBlock = compressor.compress(block)
                    Output.write(cBlock)
                    block = Input.read(2048)
                cBlock = compressor.flush()
                Output.write(cBlock)
                Input.close()
                Output.close()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)
        @staticmethod
        def tarFile(InFilePath, OutFilePath, Mode):
            try:
                tFile = tarfile.open(OutFilePath, Mode)
                tFile.add(InFilePath)
                tFile.close()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def tarDirectory(InDirectory, OutFilePath, Mode):
            try:
                Files = FileBeast.Handler.HandleDirectory(InDirectory)
                tFile = tarfile.open(OutFilePath, Mode)
                for filename in Files:
                    tFile.add(filename)
                tFile.close()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

    class Decompress:
        def __init__(self):
            pass

        @staticmethod
        def bzip(InFilePath, OutFilePath):
            try:
                with bz2.BZ2File(InFilePath, 'rb') as Input:
                    with open(OutFilePath, 'wb') as Output:
                        copyfileobj(Input, Output)
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def gzip(InFilePath, OutFilePath):
            try:
                with gzip.GzipFile(InFilePath, 'rb') as Input:
                    with open(OutFilePath, 'wb') as Output:
                        copyfileobj(Input, Output)
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def zlib(InFilePath, OutFilePath):
            try:
                decompressor = zlib.decompressobj()
                Input = file(InFilePath, 'r')
                Output = file(OutFilePath, 'w')
                block = Input.read(2048)
                while block:
                    cBlock = decompressor.decompress(block)
                    Output.write(cBlock)
                    block = Input.read(2048)
                cBlock = decompressor.flush()
                Output.write(cBlock)
                Input.close()
                Output.close()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def tar(InFilePath, OutDirectory):
            try:
                tFile = tarfile.open(InFilePath, 'r')
                tFile.extractall(OutDirectory)
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

    class Hash:
        def __init__(self):
            pass

        @staticmethod
        def sha256(password):
            hasher = SHA256.new(password)
            return hasher.digest()

        @staticmethod
        def md5(password):
            hasher = MD5.new(password)
            return hasher.digest()

    class Encode:
        def __init__(self):
            pass

        @staticmethod
        def base64(password):
            encoder = base64.b64encode(password)
            return encoder

        @staticmethod
        def reversebytes(data):
            data_size = 0
            for n in data:
                data_size += 1
            reversedbytes = bytearray()
            i = 0
            for x in range(0, data_size / 4):
                a = (data[i:i + 4])
                i += 4
                z = 0
                n0 = a[z]
                n1 = a[z + 1]
                n2 = a[z + 2]
                n3 = a[z + 3]
                reversedbytes.append(n3)
                reversedbytes.append(n2)
                reversedbytes.append(n1)
                reversedbytes.append(n0)
            return buffer(reversedbytes)

    class Encrypt:
        def __init__(self):
            pass

        @staticmethod
        def aes(InFilePath, OutFilePath, key):
            try:
                chunksize = 64 * 1024
                filesize = str(os.path.getsize(InFilePath)).zfill(16)
                IV = ''
                for i in range(16):
                    IV += chr(random.randint(0, 0xFF))
                encryptor = AES.new(key, AES.MODE_CBC, IV)
                with open(InFilePath, 'rb') as infile:
                    with open(OutFilePath, 'wb') as outputFile:
                        outputFile.write(filesize)
                        outputFile.write(IV)
                        while 1:
                            chunk = infile.read(chunksize)
                            if len(chunk) == 0:
                                break
                            elif len(chunk) % 16 != 0:
                                chunk += ' ' * (16 - (len(chunk) % 16))
                            outputFile.write(encryptor.encrypt(chunk))
                        outputFile.close()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def des3(InFilePath, OutFilePath, key):
            try:
                chunksize = 64 * 1024
                filesize = str(os.path.getsize(InFilePath)).zfill(16)
                IV = ''
                for i in range(8):
                    IV += chr(random.randint(0, 0xFF))
                encryptor = DES3.new(key, DES3.MODE_CBC, IV)
                with open(InFilePath, 'rb') as infile:
                    with open(OutFilePath, 'wb') as outputFile:
                        outputFile.write(filesize)
                        outputFile.write(IV)
                        while 1:
                            chunk = infile.read(chunksize)
                            if len(chunk) == 0:
                                break
                            elif len(chunk) % 16 != 0:
                                chunk += ' ' * (16 - (len(chunk) % 16))
                            outputFile.write(encryptor.encrypt(chunk))
                        outputFile.close()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def blowfish(InFilePath, OutFilePath, key):
            try:
                size = os.path.getsize(InFilePath)
                infile = open(InFilePath, 'rb')
                outfile = open(OutFilePath, 'wb')
                data = infile.read()
                infile.close()
                if size % 8 > 0:
                    extra = 8 - (size % 8)
                    padding = [0] * extra
                    padding = pack('b' * extra, *padding)
                    data += padding
                revdata = FileBeast.Encode.reversebytes(data)
                encrypted_data = _Blowfish.new(key, _Blowfish.MODE_ECB).encrypt(revdata)
                finaldata = FileBeast.Encode.reversebytes(encrypted_data)
                outfile.write(finaldata)
                outfile.close()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

    class Decrypt:
        def __init__(self):
            pass

        @staticmethod
        def aes(InFilePath, OutFilePath, key):
            try:
                chunksize = 64 * 1024
                with open(InFilePath, 'rb') as infile:
                    filesize = long(infile.read(16))
                    IV = infile.read(16)
                    decryptor = AES.new(key, AES.MODE_CBC, IV)
                    with open(OutFilePath, 'wb') as outputfile:
                        while 1:
                            chunk = infile.read(chunksize)
                            if len(chunk) == 0:
                                break
                            outputfile.write(decryptor.decrypt(chunk))
                        outputfile.truncate(filesize)
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def des3(InFilePath, OutFilePath, key):
            try:
                chunksize = 64 * 1024
                with open(InFilePath, 'rb') as infile:
                    filesize = long(infile.read(16))
                    IV = infile.read(8)
                    decryptor = DES3.new(key, DES3.MODE_CBC, IV)
                    with open(OutFilePath, 'wb') as outputfile:
                        while 1:
                            chunk = infile.read(chunksize)
                            if len(chunk) == 0:
                                break
                            outputfile.write(decryptor.decrypt(chunk))
                        outputfile.truncate(filesize)
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def blowfish(InFilePath, OutFilePath, key):
            try:
                infile = open(InFilePath, 'rb')
                outfile = open(OutFilePath, 'wb')
                data = infile.read()
                infile.close()
                revdata = FileBeast.Encode.reversebytes(data)
                decrypted_data = _Blowfish.new(key, _Blowfish.MODE_ECB).decrypt(revdata)
                finaldata = FileBeast.Encode.reversebytes(decrypted_data)
                end = len(finaldata) - 1
                while str(finaldata[end]).encode('hex') == '00':
                    end -= 1
                finaldata = finaldata[0:end]
                outfile.write(finaldata)
                outfile.close()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

    class Updater:
        def __init__(self):
            pass

        @staticmethod
        def checkforupdate():
            try:
                version = FileBeast.Updater.fetchurl(FileBeast.urls['version'])
                if FileBeast.__version__ == version:
                    return True
                else:
                    return False
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def update(show):
            try:
                start_time = time.time()
                if show:
                    pass
                else:
                    print Fore.LIGHTYELLOW_EX + '[*] Checking for Update...'
                version = FileBeast.Updater.checkforupdate()
                if version:
                    print Fore.GREEN + '[+] FileBeast is up to date'
                else:
                    print Fore.LIGHTYELLOW_EX + '[*] Updating FileBeast...'
                    if os.name in ('nt', 'dos'):
                        checksum = FileBeast.Updater.fetchurl(FileBeast.checksums['win32'])
                        latestfile = 'latest.exe'
                        FileBeast.Updater.fetchfile(FileBeast.urls['win32'], latestfile)
                        if FileBeast.Updater.getchecksum(latestfile) == checksum:
                            cmd = 'ping 127.0.0.1 -n 2 > nul'
                            cmd += ' && del %s && rename %s FileBeast.exe' % (sys.argv[0], latestfile)
                            subprocess.Popen(cmd, shell=True)
                        else:
                            print Fore.RED + '[-] Error while updating please try again'
                            os.remove(os.path.realpath(latestfile))
                            if show:
                                raw_input("Press Enter to continue...")
                    elif os.name in ('linux', 'posix'):
                        checksum = FileBeast.Updater.fetchurl(FileBeast.checksums['linux'])
                        latestfile = 'latest'
                        FileBeast.Updater.fetchfile(FileBeast.urls['linux'], latestfile)
                        if FileBeast.Updater.getchecksum(latestfile) == checksum:
                            cmd = 'ping 127.0.0.1 -c 2 >> /dev/null'
                            cmd += ' && rm -rf %s && mv %s FileBeast' % (sys.argv[0], latestfile)
                            cmd += ' && chmod +x FileBeast'
                            subprocess.Popen(cmd, shell=True)
                        else:
                            print Fore.RED + '[-] Error while updating please try again'
                            os.remove(os.path.realpath(latestfile))
                            if show:
                                raw_input("Press Enter to continue...")
                    else:
                        print Fore.RED + '[-] Unsupported OS'
                        print Fore.LIGHTYELLOW_EX + 'Please visit https://github.com/sepehrdaddev/FileBeast'
                        elapsed_time = time.time() - start_time
                        print Fore.GREEN + '[+] Elapsed time = %s' % elapsed_time
                        if show:
                            raw_input("Press Enter to continue...")
                        else:
                            sys.exit()
                print Fore.GREEN + '[+] Successfully Updated...'
                elapsed_time = time.time() - start_time
                print Fore.GREEN + '[+] Elapsed time = %s' % elapsed_time
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def fetchurl(url):
            try:
                return requests.get(url).content.rstrip()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def fetchfile(url, path):
            try:
                r = requests.get(url)
                data = r.content
                with open(path, "wb") as code:
                    code.write(data)
            except Exception, ErrorCode:
                os.remove(path)
                FileBeast.error(ErrorCode)

        @staticmethod
        def getchecksum(infile):
            try:
                BUF_SIZE = 65536
                sha256 = hashlib.sha256()
                with open(infile, 'rb') as f:
                    while True:
                        data = f.read(BUF_SIZE)
                        if not data:
                            break
                        sha256.update(data)
                return sha256.hexdigest()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

    class Interface:

        def __init__(self):
            pass

        @staticmethod
        def Mainmenu():
            ans = None
            while 1:
                try:
                    menu = [
                        'Encrypt',
                        'Decrypt',
                        'Compress',
                        'Decompress',
                        'Archive'
                    ]
                    FileBeast.banner()
                    print Fore.RESET + 'Select from menu: \n'
                    for i in menu:
                        print ' [%s] %s' % (menu.index(i), i)
                    print '\n [95] Update FileBeast'
                    print ' [96] Display Supported Algorithms'
                    print ' [97] Display Help'
                    print ' [98] Display Version'
                    print ' [99] Exit\n'
                    ans = raw_input(Fore.RED + "FileBeast>")
                    if ans == '0':
                        FileBeast.Interface.Encryptmenu()
                    elif ans == '1':
                        FileBeast.Interface.Decryptmenu()
                    elif ans == '2':
                        FileBeast.Interface.Compressmenu()
                    elif ans == '3':
                        FileBeast.Interface.Decompressmenu()
                    elif ans == '4':
                        FileBeast.Interface.Archivemenu()
                    elif ans == '95':
                        start_time = time.time()
                        print Fore.LIGHTYELLOW_EX + '[*] Checking for Update...'
                        version = FileBeast.Updater.checkforupdate()
                        if version:
                            print Fore.GREEN + '[+] FileBeast is up to date'
                            elapsed_time = time.time() - start_time
                            print Fore.GREEN + '[+] Elapsed time = %s' % elapsed_time
                            raw_input("Press Enter to continue...")
                        else:
                            FileBeast.Updater.update(True)
                            break
                    elif ans == '96':
                        FileBeast.showalgs(True)
                    elif ans == '97':
                        FileBeast.usage(True)
                    elif ans == '98':
                        FileBeast.version(True)
                    elif ans == '99':
                        break
                    else:
                        FileBeast.invalid(False)
                except:
                    continue
            sys.exit()

        @staticmethod
        def Encryptmenu():
            alg = ''
            infile = ''
            outfile = ''
            passwd = ''
            try:
                while 1:
                    try:
                        print 'Select encryption algorithm: \n'
                        for i in FileBeast.enc:
                            print ' [%s] %s' % (FileBeast.enc.index(i), i)
                        print ' [99] Back to Main menu\n'
                        ans = raw_input(Fore.RED + "FileBeast(Encrypt)>")
                        try:
                            ans = int(ans)
                        except:
                            FileBeast.invalid(False)
                        if ans == 99:
                            break
                        elif FileBeast.enc[ans]:
                            alg = FileBeast.enc[ans]
                            while 1:
                                try:
                                    print('Input file path: \n')
                                    ans = raw_input(Fore.RED + "FileBeast(Encrypt)>")
                                    if os.path.isfile(ans):
                                        infile = ans
                                        break
                                    else:
                                        print Fore.RED + '[-] File %s not found' % ans
                                except:
                                    continue
                            while 1:
                                try:
                                    print('Output file path: \n')
                                    ans = raw_input(Fore.RED + "FileBeast(Encrypt)>")
                                    outfile = ans
                                    break
                                except:
                                    continue
                            while 1:
                                try:
                                    passwd = getpass.getpass('Password: ')
                                    break
                                except:
                                    continue
                            break
                        else:
                            FileBeast.invalid(False)
                    except:
                        continue
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)
            if alg == 'AES':
                passwd = FileBeast.Hash.sha256(passwd)
                FileBeast.Handler.HandleOperation(FileBeast.Encrypt.aes, [infile, outfile, passwd],
                                                  ['Encrypt', infile, alg], True)
            elif alg == 'DES3':
                passwd = FileBeast.Hash.md5(passwd)
                FileBeast.Handler.HandleOperation(FileBeast.Encrypt.des3, [infile, outfile, passwd],
                                                  ['Encrypt', infile, alg], True)
            elif alg == 'BLOWFISH':
                passwd = FileBeast.Hash.sha256(passwd)
                FileBeast.Handler.HandleOperation(FileBeast.Encrypt.blowfish, [infile, outfile, passwd],
                                                  ['Encrypt', infile, alg], True)
            else:
                sys.exit()

        @staticmethod
        def Decryptmenu():
            alg = ''
            infile = ''
            outfile = ''
            passwd = ''
            try:
                while 1:
                    try:
                        print 'Select encryption algorithm: \n'
                        for i in FileBeast.enc:
                            print ' [%s] %s' % (FileBeast.enc.index(i), i)
                        print ' [99] Back to Main menu\n'
                        ans = raw_input(Fore.RED + "FileBeast(Decrypt)>")
                        try:
                            ans = int(ans)
                        except:
                            FileBeast.invalid(False)
                        if ans == 99:
                            break
                        elif FileBeast.enc[ans]:
                            alg = FileBeast.enc[ans]
                            while 1:
                                try:
                                    print('Input file path: \n')
                                    ans = raw_input(Fore.RED + "FileBeast(Decrypt)>")
                                    if os.path.isfile(ans):
                                        infile = ans
                                        break
                                    else:
                                        print Fore.RED + '[-] File %s not found' % ans
                                except:
                                    continue
                            while 1:
                                try:
                                    print('Output file path: \n')
                                    ans = raw_input(Fore.RED + "FileBeast(Decrypt)>")
                                    outfile = ans
                                    break
                                except:
                                    continue
                            while 1:
                                try:
                                    passwd = getpass.getpass('Password: ')
                                    break
                                except:
                                    continue
                            break
                        else:
                            FileBeast.invalid(False)
                    except:
                        continue
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)
            if alg == 'AES':
                passwd = FileBeast.Hash.sha256(passwd)
                FileBeast.Handler.HandleOperation(FileBeast.Decrypt.aes, [infile, outfile, passwd],
                                                  ['Decrypt', infile, alg], True)
            elif alg == 'DES3':
                passwd = FileBeast.Hash.md5(passwd)
                FileBeast.Handler.HandleOperation(FileBeast.Decrypt.des3, [infile, outfile, passwd],
                                                  ['Decrypt', infile, alg], True)
            elif alg == 'BLOWFISH':
                passwd = FileBeast.Hash.sha256(passwd)
                FileBeast.Handler.HandleOperation(FileBeast.Decrypt.blowfish, [infile, outfile, passwd],
                                                  ['Decrypt', infile, alg], True)
            else:
                sys.exit()

        @staticmethod
        def Compressmenu():
            alg = ''
            infile = ''
            outfile = ''
            level = -1
            try:
                while 1:
                    try:
                        print('Select compression algorithm: \n')
                        for i in FileBeast.cmp:
                            print ' [%s] %s' % (FileBeast.cmp.index(i), i)
                        print(' [99] Back to Main menu\n')
                        ans = raw_input(Fore.RED + "FileBeast(Compress)>")
                        try:
                            ans = int(ans)
                        except:
                            FileBeast.invalid(False)
                        if ans == 99:
                            break
                        elif FileBeast.cmp[ans]:
                            alg = FileBeast.cmp[ans]
                            while 1:
                                try:
                                    print('Input file path: \n')
                                    ans = raw_input(Fore.RED + "FileBeast(Compress)>")
                                    if os.path.isfile(ans):
                                        infile = ans
                                        break
                                    else:
                                        print Fore.RED + '[-] File %s not found' % ans
                                except:
                                    continue
                            while 1:
                                try:
                                    print('Output file path: \n')
                                    ans = raw_input(Fore.RED + "FileBeast(Compress)>")
                                    outfile = ans
                                    break
                                except:
                                    continue
                            while 1:
                                try:
                                    ans = raw_input('Compression level(0 to 9): ')
                                    try:
                                        level = int(ans)
                                    except:
                                        print Fore.RED + '[-] %s is not a valid number' % ans
                                    if level in (range(0, 10)):
                                        break
                                    else:
                                        print Fore.RED + '[-] Compression level %s is invalid' % ans
                                except:
                                    continue
                            break
                        else:
                            FileBeast.invalid(False)
                    except:
                        continue
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)
            if alg == 'BZIP':
                FileBeast.Handler.HandleOperation(FileBeast.Compress.bzip, [infile, outfile, level],
                                                  ['Compress', infile, alg], True)
            elif alg == 'GZIP':
                FileBeast.Handler.HandleOperation(FileBeast.Compress.gzip, [infile, outfile, level],
                                                  ['Compress', infile, alg], True)
            elif alg == 'ZLIB':
                FileBeast.Handler.HandleOperation(FileBeast.Compress.zlib, [infile, outfile, level],
                                                  ['Compress', infile, alg], True)
            else:
                sys.exit()

        @staticmethod
        def Decompressmenu():
            infile = ''
            outfile = ''
            alg = ''
            outdirectory = ''
            try:
                while 1:
                    try:
                        print('Select compression algorithm: \n')
                        for i in FileBeast.cmp:
                            print ' [%s] %s' % (FileBeast.cmp.index(i), i)
                        print(' [99] Back to Main menu\n')
                        ans = raw_input(Fore.RED + "FileBeast(Decompress)>")
                        try:
                            ans = int(ans)
                        except:
                            FileBeast.invalid(False)
                        if ans == 99:
                            break
                        elif FileBeast.cmp[ans]:
                            alg = FileBeast.cmp[ans]
                            while 1:
                                try:
                                    print('Input file path: \n')
                                    ans = raw_input(Fore.RED + "FileBeast(Decompress)>")
                                    if os.path.isfile(ans):
                                        infile = ans
                                        break
                                    else:
                                        print Fore.RED + '[-] File %s not found' % ans
                                except:
                                    continue
                            while 1:
                                try:
                                    if tarfile.is_tarfile(infile):
                                        print('Output directory path: \n')
                                        ans = raw_input(Fore.RED + "FileBeast(Decompress)>")
                                        outdirectory = ans
                                        break
                                    else:
                                        print('Output file path: \n')
                                        ans = raw_input(Fore.RED + "FileBeast(Decompress)>")
                                        outfile = ans
                                        break
                                except:
                                    continue
                            break
                        else:
                            FileBeast.invalid(False)
                    except:
                        continue
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)
            if tarfile.is_tarfile(infile):
                FileBeast.Handler.HandleOperation(FileBeast.Decompress.tar, [infile, outdirectory],
                                                  ['Decompress', infile, 'TAR'], True)
            elif alg == 'BZIP':
                FileBeast.Handler.HandleOperation(FileBeast.Decompress.bzip, [infile, outfile],
                                                  ['Decompress', infile, alg], True)
            elif alg == 'GZIP':
                FileBeast.Handler.HandleOperation(FileBeast.Decompress.gzip, [infile, outfile],
                                                  ['Decompress', infile, alg], True)
            elif alg == 'ZLIB':
                FileBeast.Handler.HandleOperation(FileBeast.Decompress.zlib, [infile, outfile],
                                                  ['Decompress', infile, alg], True)
            else:
                sys.exit()

        @staticmethod
        def Archivemenu():
            alg = ''
            indirectory = ''
            infile = ''
            outfile = ''
            try:
                while 1:
                    try:
                        print('Select archiving algorithm: \n')
                        for i in FileBeast.arc:
                            print ' [%s] %s' % (FileBeast.arc.index(i), i)
                        print(' [99] Back to Main menu\n')
                        ans = raw_input(Fore.RED + "FileBeast(Archive)>")
                        try:
                            ans = int(ans)
                        except:
                            FileBeast.invalid(False)
                        if ans == 99:
                            break
                        elif FileBeast.arc[ans]:
                            alg = FileBeast.arc[ans]
                            while 1:
                                try:
                                    print('Input file/directory path: \n')
                                    ans = raw_input(Fore.RED + "FileBeast(Archive)>")
                                    if os.path.isdir(ans):
                                        indirectory = ans
                                        break
                                    elif os.path.isfile(ans):
                                        infile = ans
                                        break
                                    else:
                                        print Fore.RED + '[-] Directory %s not found' % ans
                                except:
                                    continue
                            while 1:
                                try:
                                    print('Output file path: \n')
                                    ans = raw_input(Fore.RED + "FileBeast(Archive)>")
                                    outfile = ans
                                    break
                                except:
                                    continue
                            break
                        else:
                            FileBeast.invalid(False)
                    except:
                        continue
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)
            if infile != '':
                if alg == 'TAR-GZIP':
                    FileBeast.Handler.HandleOperation(FileBeast.Compress.tarFile,
                                                          [infile, outfile, 'w:gz'],
                                                          ['Archiv', infile, alg], True)
                elif alg == 'TAR-BZIP':
                    FileBeast.Handler.HandleOperation(FileBeast.Compress.tarFile,
                                                          [infile, outfile, 'w:bz2'],
                                                          ['Archiv', infile, alg], True)
                elif alg == 'TAR':
                    FileBeast.Handler.HandleOperation(FileBeast.Compress.tarFile,
                                                          [infile, outfile, 'w'],
                                                          ['Archiv', infile, alg], True)
                else:
                    sys.exit()
            elif indirectory != '':
                if alg == 'TAR-GZIP':
                    FileBeast.Handler.HandleOperation(FileBeast.Compress.tarDirectory,
                                                          [indirectory, outfile, 'w:gz'],
                                                          ['Archiv', indirectory, alg], True)
                elif alg == 'TAR-BZIP':
                    FileBeast.Handler.HandleOperation(FileBeast.Compress.tarDirectory,
                                                          [indirectory, outfile, 'w:bz2'],
                                                          ['Archiv', indirectory, alg], True)
                elif alg == 'TAR':
                    FileBeast.Handler.HandleOperation(FileBeast.Compress.tarDirectory,
                                                          [indirectory, outfile, 'w'],
                                                          ['Archiv', indirectory, alg], True)
                else:
                    sys.exit()

    class Handler:

        def __init__(self):
            pass

        @staticmethod
        def HandleOperation(operation, arg, information, show):
            try:
                start_time = time.time()
                print Fore.LIGHTYELLOW_EX + '[*] %sing %s with %s algorithm... ' % (
                information[0], information[1], information[2]),
                sys.stdout.flush()
                i = 0
                OperationThread = Thread(target=operation, args=arg)
                OperationThread.daemon = True
                OperationThread.start()
                while OperationThread.is_alive():
                    if (i % 4) == 0:
                        sys.stdout.write('\b/')
                    elif (i % 4) == 1:
                        sys.stdout.write('\b-')
                    elif (i % 4) == 2:
                        sys.stdout.write('\b\\')
                    elif (i % 4) == 3:
                        sys.stdout.write('\b|')
                    sys.stdout.flush()
                    time.sleep(0.1)
                    i += 1
                sys.stdout.write('\b')
                print Fore.GREEN + '\n[+] Successfully %sed...' % information[0]
                elapsed_time = time.time() - start_time
                while 1:
                    if show:
                        try:
                            ans = raw_input('Delete original file/directory [y/n/default=n]')
                            if ans == 'y':
                                FileBeast.rm = True
                                break
                            elif ans == 'n':
                                FileBeast.rm = False
                                break
                            elif ans == '':
                                FileBeast.rm = False
                                break
                            else:
                                FileBeast.invalid(False)
                        except:
                            continue
                    else:
                        break
                if FileBeast.rm:
                    print Fore.LIGHTYELLOW_EX + '[*] Deleting %s ' % information[1]
                    FileBeast.Handler.HandleDeletion(information[1])
                    print Fore.GREEN + '[+] Successfully Deleted %s ' % information[1]
                print Fore.GREEN + '[+] Elapsed time = %s' % elapsed_time
                if show:
                    raw_input("Press Enter to continue...")
                else:
                    sys.exit()
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def HandleDirectory(path):
            try:
                for (dirpath, _, filenames) in os.walk(path):
                    for filename in filenames:
                        yield os.path.join(dirpath, filename)
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def HandleDeletion(path):
            try:
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    for root, dirs, files in os.walk(path, topdown=False):
                        for name in files:
                            os.remove(os.path.join(root, name))
                        for name in dirs:
                            os.rmdir(os.path.join(root, name))
                    os.rmdir(path)
            except Exception, ErrorCode:
                FileBeast.error(ErrorCode)

        @staticmethod
        def HandleArgs(argv):
            opts, args = getopt.getopt(argv, 'hvusi:o:I:O:m:a:p:l:d')
            infile = ''
            outfile = ''
            indirectory = ''
            outdirectory = ''
            alg = ''
            passwd = ''
            level = -1
            stat = ''
            for opt, arg in opts:
                if opt == '-h':
                    FileBeast.usage(False)
                elif opt == '-v':
                    FileBeast.version(False)
                elif opt == '-u':
                    FileBeast.Updater.update(False)
                    sys.exit()
                elif opt == '-s':
                    FileBeast.showalgs(False)
                    sys.exit()
                elif opt == '-i':
                    if os.path.isfile(arg):
                        infile = arg
                    else:
                        print Fore.RED + '[-] File %s not found' % arg
                        sys.exit()
                elif opt == '-o':
                    outfile = arg
                elif opt == '-I':
                    if os.path.isdir(arg):
                        indirectory = arg
                    else:
                        print Fore.RED + '[-] Directory %s not found' % arg
                        sys.exit()
                elif opt == '-O':
                    outdirectory = arg
                elif opt == '-m':
                    if arg in ('encrypt', 'decrypt', 'compress', 'decompress', 'archive'):
                        stat = arg
                    else:
                        print Fore.RED + '[-] Method %s not found' % arg
                        sys.exit()
                elif opt == '-a':
                    arg = arg.upper()
                    if stat in ('encrypt', 'decrypt'):
                        if arg in FileBeast.enc:
                            alg = arg
                        else:
                            print Fore.RED + '[-] Encryption algorithm %s not found' % arg
                            sys.exit()
                    elif stat == 'compress':
                        if arg in FileBeast.cmp:
                            alg = arg
                        else:
                            print Fore.RED + '[-] Compression algorithm %s not found' % arg
                            sys.exit()
                    elif stat == 'decompress':
                        if arg in FileBeast.cmp:
                            alg = arg
                        elif arg in FileBeast.arc:
                            alg = arg
                        else:
                            print Fore.RED + '[-] Compression algorithm %s not found' % arg
                            sys.exit()
                    elif stat == 'archive':
                        if arg in FileBeast.arc:
                            alg = arg
                        else:
                            print Fore.RED + '[-] Archiving algorithm %s not found' % arg
                            sys.exit()
                    else:
                        FileBeast.invalid(True)
                elif opt == '-p':
                    passwd = arg
                elif opt == '-l':
                    try:
                        level = int(arg)
                    except:
                        print Fore.RED + '[-] %s is not a valid number' % arg
                        sys.exit()
                    if level in (range(0, 10)):
                        pass
                    else:
                        print Fore.RED + '[-] Compression level %s is invalid' % arg
                        sys.exit()
                elif opt == '-d':
                    FileBeast.rm = True
                else:
                    FileBeast.usage(False)
            if stat == 'encrypt':
                if infile == '':
                    print Fore.RED + '[-] No input file specified'
                    sys.exit()
                elif outfile == '':
                    print Fore.RED + '[-] No output file specified'
                    sys.exit()
                elif passwd == '':
                    print Fore.RED + '[-] No password specified'
                    sys.exit()
                elif level != -1 or indirectory != '' or outdirectory != '':
                    FileBeast.invalid(True)
                if alg == 'AES':
                    passwd = FileBeast.Hash.sha256(passwd)
                    FileBeast.Handler.HandleOperation(FileBeast.Encrypt.aes, [infile, outfile, passwd],
                                                      ['Encrypt', infile, alg], False)
                elif alg == 'DES3':
                    passwd = FileBeast.Hash.md5(passwd)
                    FileBeast.Handler.HandleOperation(FileBeast.Encrypt.des3, [infile, outfile, passwd],
                                                      ['Encrypt', infile, alg], False)
                elif alg == 'BLOWFISH':
                    passwd = FileBeast.Hash.sha256(passwd)
                    FileBeast.Handler.HandleOperation(FileBeast.Encrypt.blowfish, [infile, outfile, passwd],
                                                      ['Encrypt', infile, alg], False)
                else:
                    print Fore.RED + '[-] No algorithm specified'
                    sys.exit()
            elif stat == 'decrypt':
                if infile == '':
                    print Fore.RED + '[-] No input file specified'
                    sys.exit()
                elif outfile == '':
                    print Fore.RED + '[-] No output file specified'
                    sys.exit()
                elif passwd == '':
                    print Fore.RED + '[-] No password specified'
                    sys.exit()
                elif level != -1 or indirectory != '' or outdirectory != '':
                    FileBeast.invalid(True)
                if alg == 'AES':
                    passwd = FileBeast.Hash.sha256(passwd)
                    FileBeast.Handler.HandleOperation(FileBeast.Decrypt.aes, [infile, outfile, passwd],
                                                      ['Decrypt', infile, alg], False)
                elif alg == 'DES3':
                    passwd = FileBeast.Hash.md5(passwd)
                    FileBeast.Handler.HandleOperation(FileBeast.Decrypt.des3, [infile, outfile, passwd],
                                                      ['Decrypt', infile, alg], False)
                elif alg == 'BLOWFISH':
                    passwd = FileBeast.Hash.sha256(passwd)
                    FileBeast.Handler.HandleOperation(FileBeast.Decrypt.blowfish, [infile, outfile, passwd],
                                                      ['Decrypt', infile, alg], False)
                else:
                    print Fore.RED + '[-] No algorithm specified'
                    sys.exit()
            elif stat == 'compress':
                if infile == '':
                    print Fore.RED + '[-] No input file specified'
                    sys.exit()
                elif outfile == '':
                    print Fore.RED + '[-] No output file specified'
                    sys.exit()
                elif level == -1:
                    print Fore.RED + '[-] No compression level specified'
                    sys.exit()
                elif passwd != '' or indirectory != '' or outdirectory != '':
                    FileBeast.invalid(True)
                if alg == 'BZIP':
                    FileBeast.Handler.HandleOperation(FileBeast.Compress.bzip, [infile, outfile, level],
                                                      ['Compress', infile, alg], False)
                elif alg == 'GZIP':
                    FileBeast.Handler.HandleOperation(FileBeast.Compress.gzip, [infile, outfile, level],
                                                      ['Compress', infile, alg], False)
                elif alg == 'ZLIB':
                    FileBeast.Handler.HandleOperation(FileBeast.Compress.zlib, [infile, outfile, level],
                                                      ['Compress', infile, alg], False)
                else:
                    print Fore.RED + '[-] No algorithm specified'
                    sys.exit()
            elif stat == 'decompress':
                if infile == '':
                    print Fore.RED + '[-] No input file specified'
                    sys.exit()
                elif alg == '':
                    print Fore.RED + '[-] No algorithm specified'
                    sys.exit()
                elif level != -1 or passwd != '':
                    FileBeast.invalid(True)
                elif tarfile.is_tarfile(infile) and outdirectory == '':
                    print Fore.RED + '[-] No output directory specified'
                    sys.exit()
                elif not tarfile.is_tarfile(infile) and outfile == '':
                    print Fore.RED + '[-] No output file specified'
                    sys.exit()
                if tarfile.is_tarfile(infile):
                    FileBeast.Handler.HandleOperation(FileBeast.Decompress.tar, [infile, outdirectory],
                                                      ['Decompress', infile, 'TAR'], False)
                elif alg == 'BZIP':
                    FileBeast.Handler.HandleOperation(FileBeast.Decompress.bzip, [infile, outfile],
                                                      ['Decompress', infile, alg], False)
                elif alg == 'GZIP':
                    FileBeast.Handler.HandleOperation(FileBeast.Decompress.gzip, [infile, outfile],
                                                      ['Decompress', infile, alg], False)
                elif alg == 'ZLIB':
                    FileBeast.Handler.HandleOperation(FileBeast.Decompress.zlib, [infile, outfile],
                                                      ['Decompress', infile, alg], False)
                else:
                    print Fore.RED + '[-] No algorithm specified'
                    sys.exit()
            elif stat == 'archive':
                if infile == '' and indirectory == '':
                    FileBeast.invalid(True)
                elif outfile == '' and outdirectory == '':
                    FileBeast.invalid(True)
                elif level != -1 or passwd != '' or alg == '':
                    FileBeast.invalid(True)
                if alg == 'TAR-GZIP':
                    if infile != '':
                        FileBeast.Handler.HandleOperation(FileBeast.Compress.tarFile, [infile, outfile, 'w:gz'],
                                                          ['Archiv', infile, alg], False)
                    elif indirectory != '':
                        FileBeast.Handler.HandleOperation(FileBeast.Compress.tarDirectory,
                                                          [indirectory, outfile, 'w:gz'],
                                                          ['Archiv', indirectory, alg], False)
                elif alg == 'TAR-BZIP':
                    if infile != '':
                        FileBeast.Handler.HandleOperation(FileBeast.Compress.tarFile, [infile, outfile, 'w:bz2'],
                                                          ['Archiv', infile, alg], False)
                    elif indirectory != '':
                        FileBeast.Handler.HandleOperation(FileBeast.Compress.tarDirectory,
                                                          [indirectory, outfile, 'w:bz2'],
                                                          ['Archiv', indirectory, alg], False)
                elif alg == 'TAR':
                    if infile != '':
                        FileBeast.Handler.HandleOperation(FileBeast.Compress.tarFile, [infile, outfile, 'w'],
                                                          ['Archiv', infile, alg], False)
                    elif indirectory != '':
                        FileBeast.Handler.HandleOperation(FileBeast.Compress.tarDirectory,
                                                          [indirectory, outfile, 'w'],
                                                          ['Archiv', indirectory, alg], False)
                else:
                    print Fore.RED + '[-] No algorithm specified'
                    sys.exit()
            print Fore.RED + '[-] Too few arguments given'
            sys.exit()

    def __init__(self):
        self.banner()

    @staticmethod
    def invalid(show):
        print Fore.RED + '[-] Invalid option selected'
        if show:
            FileBeast.usage(False)
        else:
            raw_input("Press Enter to continue...")

    @staticmethod
    def usage(show):
        usage = '[*] Usage : FileBeast -i <inputfile> -m <method> -a <algorithm> -p <password>'
        usage += '/-l <level> -o <outputfile> -d'
        usage += '''\n                -h                      display help
                -v                      display version
                -s                      display supported algorithms
                -u                      update FileBeast
                -i                      input file path
                -I                      input directory path
                -o                      output file path
                -O                      output directory path
                -a                      encryption/compression algorithm
                -m                      set method(encrypt/decrypt/compress/decompress/archive)
                -p                      password for encryption/decryption
                -l                      level for compression(0 to 9)
                -d                      delete original file/directory
        '''
        print Fore.LIGHTYELLOW_EX + usage
        FileBeast.showalgs(False)
        example = '[*] Example : FileBeast -i test.txt -m encrypt -a AES -p password123 -o test.txt.enc'
        example += '\n[*] Example : FileBeast -i test.txt.enc -m decrypt -a AES -p password123 -o test.txt'
        example += '\n[*] Example : FileBeast -i test.txt -m compress -a gzip -l 9 -o test.txt.compressed'
        example += '\n[*] Example : FileBeast -I directory/ -m archive -a tar-gzip -o test.txt.tar.gz'
        example += '\n[*] Example : FileBeast -i test.txt.compressed -m decompress -a gzip -o test.txt'
        example += '\n[*] Example : FileBeast -i test.tar.gz -m decompress -a tar-gzip -O test/'
        print Fore.LIGHTYELLOW_EX + example
        if show:
            raw_input("Press Enter to continue...")
        else:
            sys.exit()

    @staticmethod
    def showalgs(show):
        print Fore.LIGHTYELLOW_EX + '[*] Supported Encryption Algorithms : '
        for i in FileBeast.enc:
            print Fore.LIGHTYELLOW_EX + '                                       %s\n' % i
        print Fore.LIGHTYELLOW_EX + '[*] Supported Compression Algorithms : '
        for i in FileBeast.cmp:
            print Fore.LIGHTYELLOW_EX + '                                       %s\n' % i
        print Fore.LIGHTYELLOW_EX + '[*] Supported Archiving Algorithms : '
        for i in FileBeast.arc:
            print Fore.LIGHTYELLOW_EX + '                                       %s\n' % i
        if show:
            raw_input("Press Enter to continue...")

    @staticmethod
    def error(errorcode):
        print (Fore.RED + '\n[-] Error : %s' % errorcode)
        sys.exit()

    @staticmethod
    def banner():
        print Fore.LIGHTRED_EX + ''' 	
          .                                                      .
        .n                   .                 .                  n.
  .   .dP                  dP                   9b                 9b.    .
 4    qXb         .       dX                     Xb       .        dXp     t
dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
  `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
    `9XXXXXXXXXXXP' `9XX'   FILE   `98v8P'  BEAST  `XXP' `9XXXXXXXXXXXP'
        ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                        )b.  .dbo.dP'`v'`9b.odb.  .dX(
                      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                     dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                    9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                     `'      9XXXXXX(   )XXXXXXP      `'
                              XXXX X.`v'.X XXXX
                              XP^X'`b   d'`X^XX
                              X. 9  `   '  P )X
                              `b  `       '  d'
                               `             '
                          FileBeast by Sepehrdad Sh
'''

    @staticmethod
    def version(show):
        print Fore.LIGHTYELLOW_EX + '[*] FileBeast Version %s' % FileBeast.__version__
        if show:
            raw_input("Press Enter to continue...")
        else:
            sys.exit()

if __name__ == '__main__':
    init(autoreset=True)
    try:
        if len(sys.argv[1:]) == 0:
            FileBeast.Interface.Mainmenu()
        else:
            FileBeast().Handler.HandleArgs(sys.argv[1:])
    except Exception, e:
        FileBeast.error(e)
