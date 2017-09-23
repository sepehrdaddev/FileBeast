import os
import sys
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
__filename__ = sys.argv[0]

urls = {'version': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/version',
        'win32': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Windows/FileBeast.exe',
        'linux': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Linux/FileBeast',
        'python': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/FileBeast.py'}
checksums = {'win32': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Windows/checksum',
             'linux': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/release/Linux/checksum',
             'python': 'https://raw.githubusercontent.com/sepehrdaddev/FileBeast/master/checksum'}
post_scripts = {
    'win32': {
        'python': 'ping 127.0.0.1 -n 2 > nul && del {} && rename latest.py FileBeast.py'.format(sys.argv[0]),
        'executable': 'ping 127.0.0.1 -n 2 > nul && del {} && rename latest.exe FileBeast.exe'.format(sys.argv[0])
    },
    'linux': {
        'python': 'ping 127.0.0.1 -c 2 >> /dev/null && rm -rf {} && mv latest.py FileBeast.py'.format(sys.argv[0]),
        'executable': 'ping 127.0.0.1 -c 2 >> /dev/null && rm -rf {} && mv latest FileBeast'.format(sys.argv[0])
    }
}
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
        print(Fore.RESET + "Press Enter to continue...", end='')
        input()
        return result
    return wrapper


def menu_generater(function):
    def wrapper():
        encryption_algs = ['AES', 'DES3', 'BLOWFISH']
        compression_algs = ['BZIP', 'GZIP', 'ZLIB']
        if function.__name__ in ['encrypt', 'decrypt']:
            alg = ''
            infile = ''
            outfile = ''
            passwd = ''
            while True:
                try:
                    print('\nSelect encryption algorithm: \n')
                    for i in encryption_algs:
                        print(' [%s] %s' % (encryption_algs.index(i), i))
                    print(' [3] Back to Main menu\n')
                    print("FileBeast(" + Fore.RED + function.__name__ + Fore.RESET + ")>", end='')
                    ans = input()
                    try:
                        ans = int(ans)
                    except:
                        print(Fore.RED + '[-] Invalid option selected')
                        input("Press Enter to continue...")
                        continue
                    if ans > len(encryption_algs) or ans < 0:
                        print(Fore.RED + '[-] Invalid option selected')
                        input("Press Enter to continue...")
                        continue
                    elif ans == 3:
                        break
                    elif encryption_algs[ans]:
                        alg = encryption_algs[ans]
                        while True:
                            try:
                                print('Input file path: \n')
                                print("FileBeast {}(".format(function.__name__) + Fore.RED + alg + Fore.RESET + ")>"
                                      , end='')
                                ans = input()
                                if os.path.isfile(ans):
                                    infile = ans
                                    break
                                else:
                                    print(Fore.RED + '[-] File %s not found' % ans)
                            except KeyboardInterrupt:
                                return
                        while True:
                            try:
                                print('Output file path: \n')
                                print("FileBeast {}(".format(function.__name__) + Fore.RED + alg + Fore.RESET + ")>"
                                      , end='')
                                ans = input()
                                outfile = ans
                                break
                            except KeyboardInterrupt:
                                return
                        while True:
                            try:
                                import getpass
                                passwd = getpass.getpass('Password: ')
                                break
                            except KeyboardInterrupt:
                                return
                        while True:
                            try:
                                ans = input('Would you like to hash your password ? [y/n]')
                                if ans == 'y':
                                    hashalg = ['md2', 'md4', 'md5', 'sha', 'sha256']
                                    if alg == 'DES3':
                                        hashalg.remove('sha256')
                                    print('\nSelect hashing algorithm: \n')
                                    for i in hashalg:
                                        print(' [%s] %s' % (hashalg.index(i), i.upper()))
                                    print("\nFileBeast(" + Fore.RED + "hash" + Fore.RESET + ")>", end='')
                                    ans = input()
                                    try:
                                        ans = int(ans)
                                    except:
                                        print(Fore.RED + '[-] Invalid option selected')
                                        input("Press Enter to continue...")
                                        continue
                                    if ans > (len(hashalg) - 1) or ans < 0:
                                        print(Fore.RED + '[-] Invalid option selected')
                                        input("Press Enter to continue...")
                                        continue
                                    elif hashalg[ans]:
                                        passwd = hasher(passwd, hashalg[ans])
                                        break
                                elif ans == 'n':
                                    passwd = passwd.encode('utf-8')
                                else:
                                    print(Fore.RED + '[-] Invalid option selected')
                            except KeyboardInterrupt:
                                return
                    else:
                        print(Fore.RED + '[-] Invalid option selected')
                        input("Press Enter to continue...")
                        continue
                    function(passwd, infile, outfile, alg)
                except KeyboardInterrupt:
                    return
        elif function.__name__ in ['compress', 'decompress']:
            alg = ''
            infile = ''
            outfile = ''
            if function.__name__ == 'compress':
                level = -1
            while True:
                try:
                    print('\nSelect compression algorithm: \n')
                    for i in compression_algs:
                        print(' [%s] %s' % (compression_algs.index(i), i))
                    print(' [3] Back to Main menu\n')
                    print("FileBeast(" + Fore.RED + function.__name__ + Fore.RESET + ")>", end='')
                    ans = input()
                    try:
                        ans = int(ans)
                    except:
                        print(Fore.RED + '[-] Invalid option selected')
                        input("Press Enter to continue...")
                        continue
                    if ans > len(compression_algs) or ans < 0:
                        print(Fore.RED + '[-] Invalid option selected')
                        input("Press Enter to continue...")
                        continue
                    elif ans == 3:
                        break
                    elif compression_algs[ans]:
                        alg = compression_algs[ans]
                        while True:
                            try:
                                print('Input file path: \n')
                                print("FileBeast {}(".format(function.__name__) + Fore.RED + alg + Fore.RESET + ")>"
                                      , end='')
                                ans = input()
                                if os.path.isfile(ans):
                                    infile = ans
                                    break
                                else:
                                    print(Fore.RED + '[-] File %s not found' % ans)
                            except KeyboardInterrupt:
                                return
                        while True:
                            try:
                                print('Output file path: \n')
                                print("FileBeast {}(".format(function.__name__) + Fore.RED + alg + Fore.RESET + ")>"
                                      , end='')
                                ans = input()
                                outfile = ans
                                break
                            except KeyboardInterrupt:
                                return
                        if function.__name__ == 'compress':
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
                    if function.__name__ == 'compress':
                        function(infile, outfile, level, alg)
                    elif function.__name__ == 'decompress':
                        function(infile, outfile, alg)
                except KeyboardInterrupt:
                    return
        else:
            print(Fore.RED + '[-] Error: invalid function executed')
        return
    return wrapper


@Timer
@ErrorHandler
@menu_generater
def encrypt(key, infilepath, outfilepath, method):
    print(Fore.LIGHTYELLOW_EX + 'Encrypting %s with %s algorithm...' % (infilepath, method))
    filesize = str(os.path.getsize(infilepath)).zfill(16)
    if method == 'AES':
        from Crypto.Cipher import AES
        IV = Random.new().read(AES.block_size)
        encryptor = AES.new(key, AES.MODE_CBC, IV)
    elif method == 'DES3':
        from Crypto.Cipher import DES3
        IV = Random.new().read(DES3.block_size)
        encryptor = DES3.new(key, DES3.MODE_CBC, IV)
    elif method == 'BLOWFISH':
        from Crypto.Cipher import Blowfish
        IV = Random.new().read(Blowfish.block_size)
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
@menu_generater
def decrypt(key, infilepath, outfilepath, method):
    print(Fore.LIGHTYELLOW_EX + 'Decrypting %s with %s algorithm...' % (infilepath, method))
    with open(infilepath, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)
        if method == 'AES':
            from Crypto.Cipher import AES
            decryptor = AES.new(key, AES.MODE_CBC, IV)
        elif method == 'DES3':
            from Crypto.Cipher import DES3
            decryptor = DES3.new(key, DES3.MODE_CBC, IV)
        elif method == 'BLOWFISH':
            from Crypto.Cipher import Blowfish
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
@menu_generater
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
@menu_generater
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
    elif __version__.encode('utf-8') == version:
        print(Fore.GREEN + '[+] FileBeast is up to date')
    else:
        while True:
            print(Fore.LIGHTYELLOW_EX + '[!] Update available, Would you like to update ?[y/n]: ' + Fore.RESET, end='')
            choice = input()
            if choice == 'y':
                import subprocess
                if __filename__.endswith('.py'):
                    checksum = fetchurl(checksums['python'])
                    latestfile = 'latest.py'
                    fetchfile(urls['python'], latestfile)
                    if getchecksum(latestfile).encode('utf-8') == checksum:
                        if os.name in ('nt', 'dos'):
                            subprocess.Popen(post_scripts['win32']['python'], shell=True)
                        elif os.name in ('linux', 'posix'):
                            subprocess.Popen(post_scripts['linux']['python'], shell=True)
                        else:
                            os.remove(sys.argv[0])
                            os.rename(latestfile, 'FileBeast.py')
                        sys.exit()
                    else:
                        print(Fore.RED + '[-] Error while updating please try again')
                        os.remove(os.path.realpath(latestfile))
                elif __filename__.endswith('.exe') and os.name in ('nt', 'dos'):
                    checksum = fetchurl(checksums['win32'])
                    latestfile = 'latest.exe'
                    fetchfile(urls['win32'], latestfile)
                    if getchecksum(latestfile).encode('utf-8') == checksum:
                        subprocess.Popen(post_scripts['win32']['executable'], shell=True)
                        sys.exit()
                    else:
                        print(Fore.RED + '[-] Error while updating please try again')
                        os.remove(os.path.realpath(latestfile))
                elif os.name in ('linux', 'posix'):
                    checksum = fetchurl(checksums['linux'])
                    latestfile = 'latest'
                    fetchfile(urls['linux'], latestfile)
                    if getchecksum(latestfile).encode('utf-8') == checksum:
                        subprocess.Popen(post_scripts['linux']['executable'], shell=True)
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


def hasher(text, hashalg):
    text = text.encode('utf-8')
    if hashalg == 'md2':
        from Crypto.Hash import MD2
        return MD2.new(text).digest()
    elif hashalg == 'md4':
        from Crypto.Hash import MD4
        return  MD4.new(text).digest()
    elif hashalg == 'md5':
        from Crypto.Hash import MD5
        return MD5.new(text).digest()
    elif hashalg == 'sha':
        from Crypto.Hash import SHA
        return SHA.new(text).digest()
    elif hashalg == 'sha256':
        from Crypto.Hash import SHA256
        return SHA256.new(text).digest()
    else:
        print(Fore.RED + '[-] Invalid algorithm selected')


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
        try:
            print(__banner__)
            for i in menu:
                print(' [%s] %s' % (menu.index(i), i))
            ans = input("\nFileBeast>")
            if ans == '0':
                encrypt()
            elif ans == '1':
                decrypt()
            elif ans == '2':
                compress()
            elif ans == '3':
                decompress()
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
