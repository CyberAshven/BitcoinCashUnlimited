#!/usr/bin/python2
'''
Test script for security-check.py
'''
from __future__ import division,print_function
import subprocess
import sys
import unittest

def write_testcode(filename):
    with open(filename, 'w') as f:
        f.write('''
    #include <stdio.h>
    int main()
    {
        printf("the quick brown fox jumps over the lazy god\\n");
        return 0;
    }
    ''')

def call_security_check(cc, source, executable, options):
    subprocess.check_call([cc,source,'-o',executable] + options)
    p = subprocess.Popen(['./security-check.py',executable], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    (stdout, stderr) = p.communicate()
    return (p.returncode, stdout.rstrip())

class TestSecurityChecks(unittest.TestCase):
    def test_ELF(self):
        source = 'test1.c'
        executable = 'test1'
        cc = 'gcc'
        write_testcode(source)

        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-zexecstack','-fno-stack-protector','-Wl,-znorelro','-no-pie','-fno-PIE']),
                (1, executable+': failed PIE NX RELRO Canary'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fno-stack-protector','-Wl,-znorelro','-no-pie','-fno-PIE']),
                (1, executable+': failed PIE RELRO Canary'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fstack-protector-all','-Wl,-znorelro','-no-pie','-fno-PIE']),
                (1, executable+': failed PIE RELRO'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fstack-protector-all','-Wl,-znorelro','-pie','-fPIE']),
                (1, executable+': failed RELRO'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fstack-protector-all','-Wl,-zrelro','-Wl,-z,now','-pie','-fPIE']),
                (0, ''))

    def test_64bit_PE(self):
        source = 'test1.c'
        executable = 'test1.exe'
        cc = 'x86_64-w64-mingw32-gcc'
        write_testcode(source)

        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--no-nxcompat','-Wl,--no-dynamicbase','-Wl,--no-high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed DYNAMIC_BASE HIGH_ENTROPY_VA NX RELOC_SECTION'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--no-dynamicbase','-Wl,--no-high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed DYNAMIC_BASE HIGH_ENTROPY_VA RELOC_SECTION'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--dynamicbase','-Wl,--no-high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed HIGH_ENTROPY_VA RELOC_SECTION'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--dynamicbase','-Wl,--high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed RELOC_SECTION'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--dynamicbase','-Wl,--high-entropy-va','-pie','-fPIE']),
            (0, ''))

    def test_MACHO(self):
        source = 'test1.c'
        executable = 'test1'
        cc = 'clang'
        write_testcode(source)

        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-no_pie','-Wl,-flat_namespace','-Wl,-allow_stack_execute','-fno-stack-protector']),
            (1, executable+': failed PIE NOUNDEFS NX Canary'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-no_pie','-Wl,-flat_namespace','-Wl,-allow_stack_execute','-fstack-protector-all']),
            (1, executable+': failed PIE NOUNDEFS NX'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-no_pie','-Wl,-flat_namespace','-fstack-protector-all']),
            (1, executable+': failed PIE NOUNDEFS'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-no_pie','-fstack-protector-all']),
            (1, executable+': failed PIE'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-pie','-fstack-protector-all']),
            (0, ''))

if __name__ == '__main__':
    unittest.main()

