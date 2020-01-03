#!/usr/bin/python3
# Copyright (c) 2014 Wladimir J. van der Laan
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
A script to check that the (Linux) executables produced by gitian only contain
allowed gcc, glibc and libstdc++ version symbols.  This makes sure they are
still compatible with the minimum supported Linux distribution versions.

Example usage:

    find ../gitian-builder/build -type f -executable | xargs python contrib/devtools/symbol-check.py
'''
import subprocess
import re
import sys
import os
from typing import List, Optional, Tuple

# Debian 8 (Jessie) has:
#
# - g++ version 4.9.2 (https://packages.debian.org/search?suite=default&section=all&arch=any&searchon=names&keywords=g%2B%2B)
# - libc version 2.19 (https://packages.debian.org/search?suite=default&section=all&arch=any&searchon=names&keywords=libc6)
#
# Ubuntu 14.04.6 (Trusty Tahr) has:
#
# - g++ version 4.8.2 (http://packages.ubuntu.com/search?keywords=g%2B%2B&searchon=names&suite=trusty&section=all)
# - libc version 2.19 (http://packages.ubuntu.com/search?keywords=libc6&searchon=names&suite=trusty&section=all)
#
# Taking the minimum of these as our target.
#
# According to GNU ABI document (http://gcc.gnu.org/onlinedocs/libstdc++/manual/abi.html) this corresponds to:
#   GCC 4.8.0: GCC_4.8.0
#   (glibc)    GLIBC_2_19
#
MAX_VERSIONS = {
'GCC':       (4,8,0),
'GLIBC':     (2,19),
'LIBATOMIC': (1,0)
}
# See here for a description of _IO_stdin_used:
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=634261#109

# Ignore symbols that are exported as part of every executable
IGNORE_EXPORTS = {
'_edata', '_end', '__end__', '_init', '__bss_start', '__bss_start__', '_bss_end__', '__bss_end__', '_fini', '_IO_stdin_used', 'stdin', 'stdout', 'stderr'
}
READELF_CMD = os.getenv('READELF', '/usr/bin/readelf')
CPPFILT_CMD = os.getenv('CPPFILT', '/usr/bin/c++filt')
OTOOL_CMD = os.getenv('OTOOL', '/usr/bin/otool')

# Allowed NEEDED libraries
ELF_ALLOWED_LIBRARIES = {
# bitcoind and bitcoin-qt
'libgcc_s.so.1', # GCC base support
'libc.so.6', # C library
'libpthread.so.0', # threading
'libm.so.6', # math library
'librt.so.1', # real-time (clock)
'libatomic.so.1',
'ld-linux-x86-64.so.2', # 64-bit dynamic linker
'ld-linux.so.2', # 32-bit dynamic linker
'ld-linux-aarch64.so.1', # 64-bit ARM dynamic linker
'ld-linux-armhf.so.3', # 32-bit ARM dynamic linker
'ld-linux-riscv64-lp64d.so.1', # 64-bit RISC-V dynamic linker
# bitcoin-qt only
'libxcb.so.1', # part of X11
'libxkbcommon.so.0', # keyboard keymapping
'libxkbcommon-x11.so.0', # keyboard keymapping
'libfontconfig.so.1', # font support
'libfreetype.so.6', # font parsing
'libdl.so.2', # programming interface to dynamic linker
'libxcb-icccm.so.4',
'libxcb-image.so.0',
'libxcb-shm.so.0',
'libxcb-keysyms.so.1',
'libxcb-randr.so.0',
'libxcb-render-util.so.0',
'libxcb-render.so.0',
'libxcb-shape.so.0',
'libxcb-sync.so.1',
'libxcb-xfixes.so.0',
'libxcb-xinerama.so.0',
'libxcb-xkb.so.1',
}

ARCH_MIN_GLIBC_VER = {
pixie.EM_386:    (2,1),
pixie.EM_X86_64: (2,2,5),
pixie.EM_ARM:    (2,4),
pixie.EM_AARCH64:(2,17),
}

MACHO_ALLOWED_LIBRARIES = {
# bitcoind and bitcoin-qt
'libc++.1.dylib', # C++ Standard Library
'libSystem.B.dylib', # libc, libm, libpthread, libinfo
# bitcoin-qt only
'AppKit', # user interface
'ApplicationServices', # common application tasks.
'Carbon', # deprecated c back-compat API
'ColorSync',
'CoreFoundation', # low level func, data types
'CoreGraphics', # 2D rendering
'CoreServices', # operating system services
'CoreText', # interface for laying out text and handling fonts.
'CoreVideo', # video processing
'Foundation', # base layer functionality for apps/frameworks
'ImageIO', # read and write image file formats.
'IOKit', # user-space access to hardware devices and drivers.
'IOSurface', # cross process image/drawing buffers
'libobjc.A.dylib', # Objective-C runtime library
'Metal', # 3D graphics
'Security', # access control and authentication
'QuartzCore', # animation
}

PE_ALLOWED_LIBRARIES = {
'ADVAPI32.dll', # security & registry
'IPHLPAPI.DLL', # IP helper API
'KERNEL32.dll', # win32 base APIs
'msvcrt.dll', # C standard library for MSVC
'SHELL32.dll', # shell API
'USER32.dll', # user interface
'WS2_32.dll', # sockets
# bitcoin-qt only
'dwmapi.dll', # desktop window manager
'GDI32.dll', # graphics device interface
'IMM32.dll', # input method editor
'NETAPI32.dll',
'ole32.dll', # component object model
'OLEAUT32.dll', # OLE Automation API
'SHLWAPI.dll', # light weight shell API
'USERENV.dll',
'UxTheme.dll',
'VERSION.dll', # version checking
'WINMM.dll', # WinMM audio API
'WTSAPI32.dll',
}
ARCH_MIN_GLIBC_VER = {
'80386':  (2,1),
'X86-64': (2,2,5),
'ARM':    (2,4),
'AArch64':(2,17),
'RISC-V': (2,27)
}

MACHO_ALLOWED_LIBRARIES = {
# bitcoind and bitcoin-qt
'libc++.1.dylib', # C++ Standard Library
'libSystem.B.dylib', # libc, libm, libpthread, libinfo
# bitcoin-qt only
'AppKit', # user interface
'ApplicationServices', # common application tasks.
'Carbon', # deprecated c back-compat API
'CoreFoundation', # low level func, data types
'CoreGraphics', # 2D rendering
'CoreServices', # operating system services
'CoreText', # interface for laying out text and handling fonts.
'Foundation', # base layer functionality for apps/frameworks
'ImageIO', # read and write image file formats.
'IOKit', # user-space access to hardware devices and drivers.
'libobjc.A.dylib', # Objective-C runtime library
}

class CPPFilt(object):
    '''
    Demangle C++ symbol names.

    Use a pipe to the 'c++filt' command.
    '''
    def __init__(self):
        self.proc = subprocess.Popen(CPPFILT_CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)

    def __call__(self, mangled):
        self.proc.stdin.write(mangled + '\n')
        self.proc.stdin.flush()
        return self.proc.stdout.readline().rstrip()

    def close(self):
        self.proc.stdin.close()
        self.proc.stdout.close()
        self.proc.wait()

def read_symbols(executable, imports=True) -> List[Tuple[str, str, str]]:
    '''
    Parse an ELF executable and return a list of (symbol,version, arch) tuples
    for dynamic, imported symbols.
    '''
    p = subprocess.Popen([READELF_CMD, '--dyn-syms', '-W', '-h', executable], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, universal_newlines=True)
    (stdout, stderr) = p.communicate()
    if p.returncode:
        raise IOError('Could not read symbols for {}: {}'.format(executable, stderr.strip()))
    syms = []
    for line in stdout.splitlines():
        line = line.split()
        if 'Machine:' in line:
            arch = line[-1]
        if len(line)>7 and re.match('[0-9]+:$', line[0]):
            (sym, _, version) = line[7].partition('@')
            is_import = line[6] == 'UND'
            if version.startswith('@'):
                version = version[1:]
            if is_import == imports:
                syms.append((sym, version, arch))
    return syms

def check_version(max_versions, version, arch) -> bool:
    if '_' in version:
        (lib, _, ver) = version.rpartition('_')
    else:
        lib = version
        ver = '0'
    ver = tuple([int(x) for x in ver.split('.')])
    if not lib in max_versions:
        return False
    return ver <= max_versions[lib] or lib == 'GLIBC' and ver <= ARCH_MIN_GLIBC_VER[arch]

def elf_read_libraries(filename) -> List[str]:
    p = subprocess.Popen([READELF_CMD, '-d', '-W', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, universal_newlines=True)
    (stdout, stderr) = p.communicate()
    if p.returncode:
        raise IOError('Error opening file')
    libraries = []
    for line in stdout.splitlines():
        tokens = line.split()
        if len(tokens)>2 and tokens[1] == '(NEEDED)':
            match = re.match('^Shared library: \[(.*)\]$', ' '.join(tokens[2:]))
            if match:
                libraries.append(match.group(1))
            else:
                raise ValueError('Unparseable (NEEDED) specification')
    return libraries

def check_imported_symbols(filename) -> bool:
    cppfilt = CPPFilt()
    ok = True
    for sym, version, arch in read_symbols(filename, True):
        if version and not check_version(MAX_VERSIONS, version, arch):
            print('{}: symbol {} from unsupported version {}'.format(filename, cppfilt(sym), version))
            ok = False
    return ok

def check_exported_symbols(filename) -> bool:
    cppfilt = CPPFilt()
    ok = True
    for sym,version,arch in read_symbols(filename, False):
        if arch == 'RISC-V' or sym in IGNORE_EXPORTS:
            continue
        print('{}: export of symbol {} not allowed'.format(filename, cppfilt(sym)))
        ok = False
    return ok

def check_ELF_libraries(filename) -> bool:
    ok = True
    for library_name in elf_read_libraries(filename):
        if library_name not in ELF_ALLOWED_LIBRARIES:
            print('{}: NEEDED library {} is not allowed'.format(filename, library_name))
            ok = False
    return ok

def macho_read_libraries(filename) -> List[str]:
    p = subprocess.Popen([OTOOL_CMD, '-L', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, universal_newlines=True)
    (stdout, stderr) = p.communicate()
    if p.returncode:
        raise IOError('Error opening file')
    libraries = []
    for line in stdout.splitlines():
        tokens = line.split()
        if len(tokens) == 1: # skip executable name
            continue
        libraries.append(tokens[0].split('/')[-1])
    return libraries

def check_MACHO_libraries(filename) -> bool:
    ok = True
    for dylib in macho_read_libraries(filename):
        if dylib not in MACHO_ALLOWED_LIBRARIES:
            print('{} is not in ALLOWED_LIBRARIES!'.format(dylib))
            ok = False
    return ok

CHECKS = {
'ELF': [
    ('IMPORTED_SYMBOLS', check_imported_symbols),
    ('EXPORTED_SYMBOLS', check_exported_symbols),
    ('LIBRARY_DEPENDENCIES', check_ELF_libraries)
],
'MACHO': [
    ('DYNAMIC_LIBRARIES', check_MACHO_libraries)
]
}

def identify_executable(executable) -> Optional[str]:
    with open(filename, 'rb') as f:
        magic = f.read(4)
    if magic.startswith(b'MZ'):
        return 'PE'
    elif magic.startswith(b'\x7fELF'):
        return 'ELF'
    elif magic.startswith(b'\xcf\xfa'):
        return 'MACHO'
    return None

if __name__ == '__main__':
    retval = 0
    for filename in sys.argv[1:]:
        try:
            etype = identify_executable(filename)
            if etype is None:
                print('{}: unknown format'.format(filename))
                retval = 1
                continue

            failed = []
            for (name, func) in CHECKS[etype]:
                if not func(filename):
                    failed.append(name)
            if failed:
                print('{}: failed {}'.format(filename, ' '.join(failed)))
                retval = 1
        except IOError:
            print('{}: cannot open'.format(filename))
            retval = 1
    sys.exit(retval)
