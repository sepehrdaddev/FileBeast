import os
import time
from colorama import *
from Crypto import Random

__author__ = 'Sepehrdad Sh'
__version__ = '2.0.1'
__banner__ = Fore.LIGHTRED_EX + ''' 	
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
__about__ = Fore.LIGHTRED_EX + 'FileBeast is an open source application Developed by Sepehrdad Sh used \n' \
                              'to Encrypt or Compress Files on the local disk for many purposes such as:\n' \
                              'backup and security It uses AES,TripleDES and BlowFish for \n' \
                              'Encryption algorithm and GZIP,BZIP and ZLib for Compression'

urls = {'version': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/version',
        'win32': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Windows/FileBeast.exe',
        'linux': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Linux/FileBeast'}
checksums = {'win32': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Windows/checksum',
             'linux': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Linux/checksum'}
chunksize = 64 * 1024


def ErrorHandler(function):
    def wrapper(*args, **kwargs):
        try:
            result = function(*args, **kwargs)
            return result
        except Exception as ex:
            print(Fore.RED + '\n[-] Error : %s' % ex)
            return
    return wrapper


def Timer(function):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = function(*args, **kwargs)
        elapsed_time = time.time() - start_time
        print(Fore.GREEN + '[+] Elapsed time = %s' % elapsed_time)
        return result
    return wrapper


def Pause(function):
    def wrapper(*args, **kwargs):
        result = function(*args, **kwargs)
        input(Fore.RESET + "Press Enter to continue...")
        return result
    return wrapper


@Timer
@ErrorHandler
def encrypt(key, infilepath, outfilepath, method):
    print(Fore.LIGHTYELLOW_EX + 'Encrypting %s with %s algorithm...' % (infilepath, method))
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
    else:
        print(Fore.RED + '[-] Invalid method selected')
        return
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
    print(Fore.GREEN + '[+] Successfully encrypted %s' % infilepath)
    deleter(infilepath)


@Timer
@ErrorHandler
def decrypt(key, infilepath, outfilepath, method):
    print(Fore.LIGHTYELLOW_EX + 'Decrypting %s with %s algorithm...' % (infilepath, method))
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
        else:
            print(Fore.RED + '[-] Invalid method selected')
            return
        with open(outfilepath, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)
    print(Fore.GREEN + '[+] Successfully decrypted %s' % infilepath)
    deleter(infilepath)


@Timer
@ErrorHandler
def compress(infilepath, outfilepath, level, method):
    print(Fore.LIGHTYELLOW_EX + 'Compressing %s with %s algorithm...' % (infilepath, method))
    if method == 'BZIP':
        import bz2
        from shutil import copyfileobj
        with open(infilepath, 'rb') as Input:
            with bz2.BZ2File(outfilepath, 'wb', level) as Output:
                copyfileobj(Input, Output)
    elif method == 'GZIP':
        import gzip
        from shutil import copyfileobj
        with open(infilepath, 'rb') as Input:
            with gzip.GzipFile(outfilepath, 'wb', level) as Output:
                copyfileobj(Input, Output)
    elif method == 'ZLIB':
        import zlib
        compressor = zlib.compressobj(level)
        Input = open(infilepath, 'r')
        Output = open(outfilepath, 'w')
        block = Input.read(2048)
        while block:
            cBlock = compressor.compress(block)
            Output.write(cBlock)
            block = Input.read(2048)
        cBlock = compressor.flush()
        Output.write(cBlock)
        Input.close()
        Output.close()
    else:
        print(Fore.RED + '[-] Invalid method selected')
        return
    print(Fore.GREEN + '[+] Successfully compressed %s' % infilepath)
    deleter(infilepath)


@Timer
@ErrorHandler
def decompress(infilepath, outfilepath, method):
    print(Fore.LIGHTYELLOW_EX + 'Decompressing %s with %s algorithm...' % (infilepath, method))
    if method == 'BZIP':
        import bz2
        from shutil import copyfileobj
        with bz2.BZ2File(infilepath, 'rb') as Input:
            with open(outfilepath, 'wb') as Output:
                copyfileobj(Input, Output)
    elif method == 'GZIP':
        import gzip
        from shutil import copyfileobj
        with gzip.GzipFile(infilepath, 'rb') as Input:
            with open(outfilepath, 'wb') as Output:
                copyfileobj(Input, Output)
    elif method == 'ZLIB':
        import zlib
        decompressor = zlib.decompressobj()
        Input = open(infilepath, 'r')
        Output = open(outfilepath, 'w')
        block = Input.read(2048)
        while block:
            cBlock = decompressor.decompress(block)
            Output.write(cBlock)
            block = Input.read(2048)
        cBlock = decompressor.flush()
        Output.write(cBlock)
        Input.close()
        Output.close()
    else:
        print(Fore.RED + '[-] Invalid method selected')
        return
    print(Fore.GREEN + '[+] Successfully decompressed %s' % infilepath)
    deleter(infilepath)


@ErrorHandler
def fetchurl(url):
    import requests
    return requests.get(url).content.rstrip()


def fetchfile(url, path):
    try:
        import requests
        from tqdm import tqdm
        chunk_size = 1024
        r = requests.get(url, stream=True)
        total_size = int(r.headers['content-length'])
        with open(path, 'wb') as f:
            for data in tqdm(iterable=r.iter_content(chunk_size=chunk_size), total=total_size / chunk_size,
                             unit='KB'):
                f.write(data)
    except Exception:
        os.remove(path)
        print(Fore.RED + 'Error while downloading file')


@ErrorHandler
def getchecksum(filepath):
    import hashlib
    BUF_SIZE = 65536
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()


@Timer
@ErrorHandler
@Pause
def checkforupdate():
    print(Fore.LIGHTYELLOW_EX + '[*] Checking for Update...')
    version = fetchurl(urls['version'])
    if version is None:
        return
    elif __version__ == version:
        print(Fore.GREEN + '[+] FileBeast is up to date')
    else:
        while True:
            print(Fore.LIGHTYELLOW_EX + '[!] Update available, Would you like to update ?[y/n]: ' + Fore.RESET, end='')
            choice = input()
            if choice == 'y':
                import subprocess
                import sys
                if os.name in ('nt', 'dos'):
                    checksum = fetchurl(checksums['win32'])
                    latestfile = 'latest.exe'
                    fetchfile(urls['win32'], latestfile)
                    if getchecksum(latestfile).encode('utf-8') == checksum:
                        subprocess.Popen('ping 127.0.0.1 -n 2 > nul && del %s && rename %s FileBeast.exe '
                                         '&& start FileBeast.exe' % (sys.argv[0], latestfile), shell=True)
                        sys.exit()
                    else:
                        print(Fore.RED + '[-] Error while updating please try again')
                        os.remove(os.path.realpath(latestfile))
                elif os.name in ('linux', 'posix'):
                    checksum = fetchurl(checksums['linux'])
                    latestfile = 'latest'
                    fetchfile(urls['linux'], latestfile)
                    if getchecksum(latestfile).encode('utf-8') == checksum:
                        subprocess.Popen('ping 127.0.0.1 -c 2 >> /dev/null && rm -rf %s && mv %s FileBeast '
                                         '&& chmod +x FileBeast && ./FileBeast' % (sys.argv[0], latestfile), shell=True)
                        sys.exit()
                    else:
                        print(Fore.RED + '[-] Error while updating please try again')
                        os.remove(os.path.realpath(latestfile))
                else:
                    print(Fore.RED + '[-] Unsupported OS')
                    print(Fore.LIGHTYELLOW_EX + 'Please visit https://github.com/sepehrdaddev/FileBeast')
                break
            elif choice == 'n':
                break
            else:
                print(Fore.RED + '[-] Invalid option selected')
                continue


def main_menu():
    menu = [
        'Encrypt',
        'Decrypt',
        'Compress',
        'Decompress',
        'Update',
        'Version',
        'About',
        'Exit'
    ]
    while True:
        print(__banner__)
        for i in menu:
            print(' [%s] %s' % (menu.index(i), i))
        ans = input("\nFileBeast>")
        if ans == '0':
            encrypt_menu()
        elif ans == '1':
            decrypt_menu()
        elif ans == '2':
            compress_menu()
        elif ans == '3':
            decompress_menu()
        elif ans == '4':
            checkforupdate()
        elif ans == '5':
            print(__banner__)
            print(Fore.LIGHTYELLOW_EX + '[*] FileBeast Version %s' % __version__)
            input("Press Enter to continue...")
        elif ans == '6':
            print(__banner__)
            print(__about__)
            input("Press Enter to continue...")
        elif ans == '7':
            print(__banner__)
            print(Fore.LIGHTYELLOW_EX + '[!] Exitting...')
            break
        else:
            print(Fore.RED + '[-] Invalid option selected')
            input("Press Enter to continue...")
            continue
        continue


def encrypt_menu():
    algs = ['AES', 'DES3', 'BLOWFISH']
    alg = ''
    infile = ''
    outfile = ''
    passwd = ''
    while True:
        try:
            print('\nSelect encryption algorithm: \n')
            for i in algs:
                print(' [%s] %s' % (algs.index(i), i))
            print(' [3] Back to Main menu\n')
            ans = input("FileBeast(" + Fore.RED + "Encrypt" + Fore.RESET + ")>")
            try:
                ans = int(ans)
            except:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            if ans > len(algs) or ans < 0:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            elif ans == 3:
                break
            elif algs[ans]:
                alg = algs[ans]
                while True:
                    try:
                        print('Input file path: \n')
                        ans = input("FileBeast(" + Fore.RED + alg + Fore.RESET + ")>")
                        if os.path.isfile(ans):
                            infile = ans
                            break
                        else:
                            print(Fore.RED + '[-] File %s not found' % ans)
                    except KeyboardInterrupt:
                        continue
                while True:
                    try:
                        print('Output file path: \n')
                        ans = input("FileBeast(" + Fore.RED + alg + Fore.RESET + ")>")
                        outfile = ans
                        break
                    except KeyboardInterrupt:
                        continue
                while True:
                    try:
                        import getpass
                        passwd = getpass.getpass('Password: ')
                        break
                    except KeyboardInterrupt:
                        continue
            else:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            encrypt(passwd, infile, outfile, alg)
        except KeyboardInterrupt:
            continue


def decrypt_menu():
    algs = ['AES', 'DES3', 'BLOWFISH']
    alg = ''
    infile = ''
    outfile = ''
    passwd = ''
    while True:
        try:
            print('\nSelect encryption algorithm: \n')
            for i in algs:
                print(' [%s] %s' % (algs.index(i), i))
            print(' [3] Back to Main menu\n')
            ans = input("FileBeast(" + Fore.RED + "Decrypt" + Fore.RESET + ")>")
            try:
                ans = int(ans)
            except:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            if ans > len(algs) or ans < 0:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            elif ans == 3:
                break
            elif algs[ans]:
                alg = algs[ans]
                while True:
                    try:
                        print('Input file path: \n')
                        ans = input("FileBeast(" + Fore.RED + alg + Fore.RESET + ")>")
                        if os.path.isfile(ans):
                            infile = ans
                            break
                        else:
                            print(Fore.RED + '[-] File %s not found' % ans)
                    except KeyboardInterrupt:
                        continue
                while True:
                    try:
                        print('Output file path: \n')
                        ans = input("FileBeast(" + Fore.RED + alg + Fore.RESET + ")>")
                        outfile = ans
                        break
                    except KeyboardInterrupt:
                        continue
                while True:
                    try:
                        import getpass
                        passwd = getpass.getpass('Password: ')
                        break
                    except KeyboardInterrupt:
                        continue
            else:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            decrypt(passwd, infile, outfile, alg)
        except KeyboardInterrupt:
            continue


def compress_menu():
    algs = ['BZIP', 'GZIP', 'ZLIB']
    alg = ''
    infile = ''
    outfile = ''
    level = -1
    while True:
        try:
            print('\nSelect compression algorithm: \n')
            for i in algs:
                print(' [%s] %s' % (algs.index(i), i))
            print(' [3] Back to Main menu\n')
            ans = input("FileBeast(" + Fore.RED + "Compress" + Fore.RESET + ")>")
            try:
                ans = int(ans)
            except:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            if ans > len(algs) or ans < 0:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            elif ans == 3:
                break
            elif algs[ans]:
                alg = algs[ans]
                while True:
                    try:
                        print('Input file path: \n')
                        ans = input("FileBeast(" + Fore.RED + alg + Fore.RESET + ")>")
                        if os.path.isfile(ans):
                            infile = ans
                            break
                        else:
                            print(Fore.RED + '[-] File %s not found' % ans)
                    except KeyboardInterrupt:
                        continue
                while True:
                    try:
                        print('Output file path: \n')
                        ans = input("FileBeast(" + Fore.RED + alg + Fore.RESET + ")>")
                        outfile = ans
                        break
                    except KeyboardInterrupt:
                        continue
                while True:
                    try:
                        ans = input('Compression level(0 to 9): ')
                        try:
                            level = int(ans)
                        except:
                            print(Fore.RED + '[-] %s is not a valid number' % ans)
                        if level in (range(0, 10)):
                            break
                        else:
                            print(Fore.RED + '[-] Compression level %s is invalid' % ans)
                    except:
                        continue
            else:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            compress(infile, outfile, level, alg)
        except KeyboardInterrupt:
            continue


def decompress_menu():
    algs = ['BZIP', 'GZIP', 'ZLIB']
    alg = ''
    infile = ''
    outfile = ''
    while True:
        try:
            print('\nSelect compression algorithm: \n')
            for i in algs:
                print(' [%s] %s' % (algs.index(i), i))
            print(' [3] Back to Main menu\n')
            ans = input("FileBeast(" + Fore.RED + "Decompress" + Fore.RESET + ")>")
            try:
                ans = int(ans)
            except:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            if ans > len(algs) or ans < 0:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            elif ans == 3:
                break
            elif algs[ans]:
                alg = algs[ans]
                while True:
                    try:
                        print('Input file path: \n')
                        ans = input("FileBeast(" + Fore.RED + alg + Fore.RESET + ")>")
                        if os.path.isfile(ans):
                            infile = ans
                            break
                        else:
                            print(Fore.RED + '[-] File %s not found' % ans)
                    except KeyboardInterrupt:
                        continue
                while True:
                    try:
                        print('Output file path: \n')
                        ans = input("FileBeast(" + Fore.RED + alg + Fore.RESET + ")>")
                        outfile = ans
                        break
                    except KeyboardInterrupt:
                        continue
            else:
                print(Fore.RED + '[-] Invalid option selected')
                input("Press Enter to continue...")
                continue
            decompress(infile, outfile, alg)
        except KeyboardInterrupt:
            continue


@ErrorHandler
def deleter(infile):
    while True:
        print(Fore.LIGHTYELLOW_EX + '[!] Would you like to delete original file ?[y/n]: ' + Fore.RESET, end='')
        choice = input()
        if choice == 'y':
            print(Fore.LIGHTYELLOW_EX + '[*] Deleting %s ' % infile)
            os.remove(infile)
            print(Fore.GREEN + '[+] Successfully Deleted %s ' % infile)
            break
        elif choice == 'n':
            break


if __name__ == '__main__':
    init(autoreset=True)
    main_menu()
