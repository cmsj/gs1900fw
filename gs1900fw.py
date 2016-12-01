#!/usr/bin/env python
"""ZyXEL GS1900 Firmware Tool"""

import argparse
import binascii
import datetime
import struct
import sys

# Operating System Codes
IH_OS_INVALID = 0    # Invalid OS
IH_OS_OPENBSD = 1    # OpenBSD
IH_OS_NETBSD = 2    # NetBSD
IH_OS_FREEBSD = 3    # FreeBSD
IH_OS_4_4BSD = 4    # 4.4BSD
IH_OS_LINUX = 5    # Linux
IH_OS_SVR4 = 6    # SVR4
IH_OS_ESIX = 7    # Esix
IH_OS_SOLARIS = 8    # Solaris
IH_OS_IRIX = 9    # Irix
IH_OS_SCO = 10    # SCO
IH_OS_DELL = 11    # Dell
IH_OS_NCR = 12    # NCR
IH_OS_LYNXOS = 13    # LynxOS
IH_OS_VXWORKS = 14    # VxWorks
IH_OS_PSOS = 15    # pSOS
IH_OS_QNX = 16    # QNX
IH_OS_U_BOOT = 17    # Firmware
IH_OS_RTEMS = 18    # RTEMS
IH_OS_ARTOS = 19    # ARTOS
IH_OS_UNITY = 20    # Unity OS
IH_OS_INTEGRITY = 21    # INTEGRITY

# Array containig the string with OS Names
# Corresponding to the ih_os numeric value
IH_OS_LOOKUP = [
    'Invalid OS',
    'OpenBSD',
    'NetBSD',
    'FreeBSD',
    '4.4BSD',
    'Linux',
    'SVR4',
    'Esix',
    'Solaris',
    'Irix',
    'SCO',
    'Dell',
    'NCR',
    'LynxOS',
    'VxWorks',
    'pSOS',
    'QNX',
    'Firmware',
    'RTEMS',
    'ARTOS',
    'Unity',
    'INTEGRITY'
]

# CPU Architecture Codes (supported by Linux)
IH_ARCH_INVALID = 0    # Invalid CPU
IH_ARCH_ALPHA = 1    # Alpha
IH_ARCH_ARM = 2    # ARM
IH_ARCH_I386 = 3    # Intel x86
IH_ARCH_IA64 = 4    # IA64
IH_ARCH_MIPS = 5    # MIPS
IH_ARCH_MIPS64 = 6    # MIPS 64 Bit
IH_ARCH_PPC = 7    # PowerPC
IH_ARCH_S390 = 8    # IBM S390
IH_ARCH_SH = 9    # SuperH
IH_ARCH_SPARC = 10    # Sparc
IH_ARCH_SPARC64 = 11    # Sparc 64 Bit
IH_ARCH_M68K = 12    # M68K
IH_ARCH_NIOS = 13    # Nios-32
IH_ARCH_MICROBLAZE = 14    # MicroBlaze
IH_ARCH_NIOS2 = 15    # Nios-II
IH_ARCH_BLACKFIN = 16    # Blackfin
IH_ARCH_AVR32 = 17    # AVR32
IH_ARCH_ST200 = 18    # STMicroelectronics ST200

# Array containig the string with Architecture Names
# Corresponding to the ih_arch numeric value
IH_ARCH_LOOKUP = [
    'Invalid',
    'Alpha',
    'ARM',
    'Intel',
    'IA64',
    'MIPS',
    'MIPS',
    'PowerPC',
    'IBM',
    'SuperH',
    'Sparc',
    'Sparc',
    'M68K',
    'Nios-32',
    'MicroBlaze',
    'Nios-II',
    'Blackfin',
    'AVR32',
    'STMicroelectronics'
]

IH_TYPE_INVALID = 0    # Invalid Image
IH_TYPE_STANDALONE = 1    # Standalone Program
IH_TYPE_KERNEL = 2    # OS Kernel Image
IH_TYPE_RAMDISK = 3    # RAMDisk Image
IH_TYPE_MULTI = 4    # Multi-File Image
IH_TYPE_FIRMWARE = 5    # Firmware Image
IH_TYPE_SCRIPT = 6    # Script file
IH_TYPE_FILESYSTEM = 7    # Filesystem Image (any type)
IH_TYPE_FLATDT = 8    # Binary Flat Device Tree Blob
IH_TYPE_KWBIMAGE = 9    # Kirkwood Boot Image

IH_TYPE_LOOKUP = [
    'Invalid Image',
    'Standalone Program',
    'OS Kernel Image',
    'RAMDisk Image',
    'Multi-File Image',
    'Firmware Image',
    'Script file',
    'Filesystem Image (any type)',
    'Binary Flat Device Tree Blob',
    'Kirkwood Boot Image'
]

# Compression Types
IH_COMP_NONE = 0    # No Compression Used
IH_COMP_GZIP = 1    # gzip Compression Used
IH_COMP_BZIP2 = 2    # bzip2 Compression Used
IH_COMP_LZMA = 3    # lzma Compression Used

IH_COMP_LOOKUP = ['None', 'gzip', 'bzip2', 'lzma']
IH_COMP_EXT_LOOKUP = ['dat', 'gz', 'bz2', 'lzma']

# IH_MAGIC = 0x27051956    # Image Magic Number
IH_MAGIC = 0x83800000  # ZyXEL are using their own magic for some reason
IH_NMLEN = 32    # Image Name Length

IH_HCRC_XOR = 0x9F3FF3D7  # ZyXEL seem to XOR the ih_hcrc with this


def parse_options(args=None):
    """Parse command line arguments"""
    formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(description="Inspect/manipulate ZyXEL \
                                                 GS1900 firmware files",
                                     formatter_class=formatter)
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        dest="debug",
                        default=False,
                        help="Turn on debugging output")
    parser.add_argument("-n", "--dry-run",
                        action="store_true",
                        dest="dryrun",
                        default=False,
                        help="Run in simulation mode")
    parser.add_argument("-w", "--file",
                        action="store",
                        dest="firmware_file",
                        default=None,
                        help="Path to the firmware file")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--info",
                       action="store_true",
                       dest="info",
                       default=False,
                       help="Show all available information about a firmware")
    group.add_argument("-e", "--extract",
                       action="store_true",
                       dest="extract",
                       default=False,
                       help="Extract the contents of the firmware file")
    group.add_argument("-c", "--verify-checksums",
                       action="store_true",
                       dest="checksums",
                       default=False,
                       help="Verifies the checksums of a firmware")

    args = parser.parse_args(args)
    return args


def asHex(value):
    """Turn an integer into a hex string"""
    return format(value, '#02x')

def asBytes(value, length):
    """Turn an integer into a byte array"""
    return value.to_bytes(length, byteorder="big", signed=False)


class UBootImage(object):
    """Class for interacting with UBoot image files"""
    def __init__(self):
        """Constructor"""
        self.ih_magic = 0  # Image Header Magic Number
        self.ih_hcrc = 0  # Image Header CRC Checksum
        self.ih_time = 0  # Image Creation Timestamp
        self.ih_size = 0  # Image Data Size
        self.ih_load = 0  # Data     Load  Address
        self.ih_ep = 0  # Entry Point Address
        self.ih_dcrc = 0  # Image Data CRC Checksum
        self.ih_os = 0  # Operating System
        self.ih_arch = 0  # CPU architecture
        self.ih_type = 0  # Image Type
        self.ih_comp = 0  # Compression Type
        self.ih_name = ''  # Image Name
        self.parts = []  # Image parts
        self.raw_header = None  # Raw 64 byte header
        self.raw_image = None  # Raw image

    def lookup_magic(self, lookup, item):
        """Utility method to use this libraries lookup tables"""
        if item < 0 or item >= len(lookup):
            return '<not supported %02X>' % item
        return lookup[item]

    def os_name(self): return self.lookup_magic(IH_OS_LOOKUP, self.ih_os)

    def arch_name(self): return self.lookup_magic(IH_ARCH_LOOKUP, self.ih_arch)

    def type_name(self): return self.lookup_magic(IH_TYPE_LOOKUP, self.ih_type)

    def comp_name(self): return self.lookup_magic(IH_COMP_LOOKUP, self.ih_comp)

    def load_fw(self, filepath):
        """Load a firmware file from disk"""
        print "Loading: %s" % filepath
        with open(filepath, "rb") as fwfile:
            self.raw_header = fwfile.read(64)
            self.raw_image = fwfile.read()

    def parse_header(self):
        """Parse the image header values"""
        header = struct.unpack(">IIIIIIIBBBB32s", self.raw_header)
        self.ih_magic = header[0]
        self.ih_hcrc = header[1]
        self.ih_time = header[2]
        self.ih_size = header[3]
        self.ih_load = header[4]
        self.ih_ep = header[5]
        self.ih_dcrc = header[6]
        self.ih_os = header[7]
        self.ih_arch = header[8]
        self.ih_type = header[9]
        self.ih_comp = header[10]
        self.ih_name = header[11]

        print("Checking file magic: Expected %s, found %s" % (
            asHex(IH_MAGIC),
            asHex(self.ih_magic))
             )

    def parse_image(self):
        """Parse the image"""
        if self.ih_type == IH_TYPE_MULTI:
            print "ERROR: Unable to handle multipart images, sorry!"
            sys.exit(1)

        self.parts.append(self.raw_image)

    def fwinfo(self):
        """Collect information about the firmware, as a string"""
        info = ""
        info += "Firmware name: %s\n" % self.ih_name
        timestamp = datetime.datetime.fromtimestamp(self.ih_time)
        timestr = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        info += "Creation time: %s UTC\n" % timestr
        info += "Image size: %s bytes\n" % self.ih_size
        info += "Image type: %s\n" % self.type_name()
        info += "Compression type: %s\n" % self.comp_name()
        info += "Architecture: %s\n" % self.arch_name()
        info += "OS: %s\n" % self.os_name()
        info += "Load address: %s\n" % asHex(self.ih_load)
        info += "Execution address: %s\n" % asHex(self.ih_ep)
        return info

    def checksums(self):
        """Check the checksums of header and image"""
        success = True

        header_crc = (binascii.crc32(self.raw_header[8:64]) & 0xFFFFFFFF) ^ IH_HCRC_XOR
        print("Header checksum: Expected %s, found %s" % (
            asHex(self.ih_hcrc),
            asHex(header_crc)))
        if self.ih_hcrc != header_crc:
            self.err("Header CRCs do not match", exit=False)
            success = False

        image_crc = binascii.crc32(self.parts[0]) & 0xFFFFFFFF
        print("Image checksum: Expected %s, found %s" % (
            asHex(self.ih_dcrc),
            asHex(image_crc)))
        if self.ih_dcrc != image_crc:
            self.err("Image CRCs do not match", exit=False)
            success = True

        return success

class GS1900FW(object):
    """Main class"""
    options = None
    uboot = None

    def __init__(self, options):
        """Class initialiser"""
        self.uboot = UBootImage()
        self.options = options
        self.dbg("Command line arguments: %s" % self.options)

        if self.options.firmware_file:
            self.uboot.load_fw(self.options.firmware_file)

    def err(self, msg, exit=True):
        """Print an error and die"""
        print("ERROR: %s" % msg)
        if exit:
            sys.exit(1)

    def dbg(self, msg):
        """Print a debugging message, if appropriate"""
        if self.options.debug:
            print "DEBUG: %s" % msg

    def parse_fw(self):
        """Parse a firmware and return a useful data structure"""
        self.uboot.parse_header()
        self.uboot.parse_image()

        if self.uboot.ih_magic != IH_MAGIC:
            self.err("File does not appear to be a valid firmware",
                     False)
            return False
        else:
            return True

    def do_checksums(self):
        """Validate the checksums in a file"""
        if not self.options.firmware_file:
            self.err("No firmware file specified, see --help")

        self.parse_fw()
        print self.uboot.fwinfo()
        if not self.uboot.checksums():
            self.err("Some checksum operations failed")
        else:
            print("Checksum tests PASSED!")


def main():
    """Main entry point"""
    options = parse_options()
    gs1900fw = GS1900FW(options)

    if options.checksums:
        return gs1900fw.do_checksums()


if __name__ == "__main__":
    main()
