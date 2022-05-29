#!/usr/bin/python3
import zlib
import argparse
import binascii
from io import BytesIO
from dissect.cstruct import cstruct

cfbs_type = {
"CBFS_TYPE_DELETED" : 0x00000000,
"CBFS_TYPE_NULL" : 0xffffffff,
"CBFS_TYPE_BOOTBLOCK" : 0x01,
"CBFS_TYPE_CBFSHEADER" : 0x02,
"CBFS_TYPE_LEGACY_STAGE" : 0x10,
"CBFS_TYPE_STAGE" : 0x11,
"CBFS_TYPE_SELF" : 0x20,
"CBFS_TYPE_FIT" : 0x21,
"CBFS_TYPE_OPTIONROM" : 0x30,
"CBFS_TYPE_BOOTSPLASH" : 0x40,
"CBFS_TYPE_RAW" : 0x50,
"CBFS_TYPE_VSA" : 0x51,
"CBFS_TYPE_MBI" : 0x52,
"CBFS_TYPE_MICROCODE" : 0x53,
"CBFS_TYPE_FSP" : 0x60,
"CBFS_TYPE_MRC" : 0x61,
"CBFS_TYPE_MMA" : 0x62,
"CBFS_TYPE_EFI" : 0x63,
"CBFS_TYPE_STRUCT" : 0x70,
"CBFS_TYPE_CMOS_DEFAULT" : 0xaa,
"CBFS_TYPE_SPD" : 0xab,
"CBFS_TYPE_MRC_CACHE" : 0xac,
"CBFS_TYPE_CMOS_LAYOUT" : 0x01aa,
}


cdef = """
struct cbfs_file {
     char magic[8]; /* LARCHIVE */
     uint32 len;
     uint32 type;
     uint32 checksum;
     uint32 offset;
     char filename[offset - 0x19];
};

struct cbfs_header {
        char magic[4];
        char version[4];
        uint32 romsize;
        uint32 bootblocksize;
        uint32 align;
        uint32 offset;
        uint32 architecture;
        uint32 pad[1];
};

struct cbfs_stage {
         uint32 compression;
         uint64 entry;
         uint64 load;
         uint32 len;
         uint32 memlen;
};

struct cbfs_payload_segment {
         uint32 type;
         uint32 compression;
         uint32 offset;
         uint64 load_addr;
         uint32 len;
         uint32 mem_len;
};

struct cbfs_payload {
         struct cbfs_payload_segment segments;
};
"""

c_cbfs = cstruct(endian=">")
c_cbfs.load(cdef, compiled=True)


class CoreBootFileSystem(object):
    def __init__(self, fh, extract=False):
        self.fh = fh
        self.mheader = MasterHeader(fh)
        self.cbfscomps = CoreBoot_Components(fh, offset=self.mheader.offset, extract=extract)


class CoreBoot_File(object):
    def __init__(self, fh, extract=False):
        self.fh = fh
        self.parseoffset = fh.tell()
        self.struct = c_cbfs.cbfs_file(fh)

        self.magic = self.struct.magic
        self.len = self.struct.len
        self.type = self.struct.type
        self.checksum = self.struct.checksum
        self.offset = self.struct.offset
        self.filename = self.struct.filename.replace(b"\00", b"").decode()
        if extract:
            with open(f"{args.destination}/{self.filename}", "wb") as output_file:
                fh.seek(1, 1)
                data = fh.read(self.len)
                output_file.write(data)

    def __repr__(self):
        return repr(self.struct)


class CoreBoot_Components(object):
    def findnext(self, fh):
        search = fh.read(0x40)
        if b"LARCHIVE" in search:
            fh.seek((-0x40 + search.index(b"LARCHIVE")), 1)
            return 1

    def __init__(self, fh, offset=None, extract=False):
        self.fh = fh
        self.components = []
        self.compcounts = len(fh.getvalue())
        fh.seek(offset)
        for i in range(self.compcounts):
            if self.findnext(fh):
                self.components.append(CoreBoot_File(fh, extract=extract))

    # def __str__(self):


class MasterHeader(object):
    def __init__(self, fh):
        self.fh = fh
        self.headeroffset = fh.getvalue().find(b"ORBC")

        if self.headeroffset >= 0:
            fh.seek(self.headeroffset)
            self.struct = c_cbfs.cbfs_header(fh)

            self.magic = self.struct.magic
            self.version = self.struct.version
            self.romsize = self.struct.romsize
            self.bootblocksize = self.struct.bootblocksize
            self.align = self.struct.align
            self.offset = self.struct.offset
            self.architecture = self.struct.architecture
            self.pad = self.struct.pad
        else:
            print("Master Header could not be found")
            exit(1)


def setup_argparse():
    parser = argparse.ArgumentParser(description="A tool for parsing CBFS")

    parser.add_argument("file", help="input file")

    # Adding subparser
    subparsers = parser.add_subparsers(help="functions", dest="function", required=True)

    # volatility subparser
    printdat = subparsers.add_parser(
        "print", help="Prints all information for the cbfs"
    )

    exportdat = subparsers.add_parser(
        "extract", help="extracts all LARCHIVE's from the cbfs"
    )
    destfolder = exportdat.add_argument(
        "-D","--destination", help="Destination folder for extracting", required=True
    )

    return parser.parse_args()


def checktype(comtype):
    for key in cfbs_type:
        if comtype == cfbs_type[key]:
            return key.replace("CBFS_TYPE_","")

def printvalues(components):
    printformat = "{:<32} {:<8}   {:<10} {:<8} {:<4}"
    print(printformat.format("Name", "Offset", "Type", "Size", "Comp"))
    printformat = "{:<32} {:>8}   {:<10} {:>8} {:<4}"
    for component in components:
        print(
            printformat.format(
                component.filename,
                hex(component.parseoffset),
                checktype(component.type),
                component.len,
                "lzma" if component.filename[-5:].lower() == ".lzma" else "unknown",
            )
        )


if __name__ == "__main__":
    args = setup_argparse()
    d = BytesIO(open(args.file, "rb").read())

    if args.function == "print":
        cbfs = CoreBootFileSystem(d)
        printvalues(cbfs.cbfscomps.components)

    elif args.function == 'extract':
        cbfs = CoreBootFileSystem(d, extract=True)
                
