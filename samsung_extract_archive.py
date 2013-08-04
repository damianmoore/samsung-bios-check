#!/usr/bin/env python2.7

import sys
import os
import argparse
import struct
from contextlib import closing

import pefile

LPCK_MAGIC = 'LPCK'

class LPCKFormatError(Exception):
    """Unrecognised file format"""
    pass

class LPCKHeader(pefile.Structure):
    """LPCK archive header"""
    def __init__(self):
        fmt = ('LPCK_HEADER', ('L,e_magic', '536s,e_reserved', 'L,e_count'))
        pefile.Structure.__init__(self, fmt)
        
    def unpack(self, data):
        self.__unpack__(data)


class FileHeader(pefile.Structure):
    """LPCK archive file header"""
    def __init__(self):
        fmt = ('FILE_HEADER', ('520s,e_path', 'L,e_size'))
        pefile.Structure.__init__(self, fmt)
        
    def unpack(self, data):
        self.__unpack__(data)
        
        
def seek_lpck_header(f):
    """Find LPCK offset and then seek to it"""
    with closing(pefile.PE(f.name)) as pe:
        offset = pe.get_dword_from_offset(pe.DOS_HEADER.get_field_absolute_offset('e_res2'))
        f.seek(offset)


def read_lpck_header(f):
    """read / parse lpck header"""
    lpck_header = LPCKHeader()
    data = f.read(lpck_header.sizeof())
    lpck_header.unpack(data)
    
    # check the start of data is as expected
    if struct.pack('<L', lpck_header.e_magic) != LPCK_MAGIC:
        raise LPCKFormatError
    
    return lpck_header

def read_file_header(f, list_only):
    """read lpck archive file entry header"""
    header = FileHeader()
    data = f.read(header.sizeof())
    header.unpack(data)
    
    path = header.e_path.decode('utf-16').strip('\00')
    header.e_path = path
    
    if list_only:
        print >>sys.stderr, "File: {}".format(path)
    else:
        print >>sys.stderr, "Extracting File: {}".format(path)

    return header

def extract_file(f, list_only):
    """extract the file from/at the current file position"""
    file_header = read_file_header(f, list_only)
    if list_only:
        f.seek(file_header.e_size, os.SEEK_CUR)
        return
    
    data = f.read(file_header.e_size)
    with open(file_header.e_path, 'w') as g:
        g.write(data)

        
def extract(f, list_only=False):
    seek_lpck_header(f)

    lpck_header = read_lpck_header(f)
    for x in xrange(lpck_header.e_count):
        extract_file(f, list_only)
            


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="the path to the archive / exe")
    parser.add_argument("-l", "--list", help="list archive contents", action="store_true")
    args = parser.parse_args()
   
    print >>sys.stderr, "Opening / Extracting: {}".format(args.path)
    with open(args.path) as f:
        extract(f, args.list)

if __name__ == '__main__':
    main()
