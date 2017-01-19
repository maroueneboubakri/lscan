'''
lscan is a tool which identifying library in statically linked/stripped binaries.
The tool is useful for the reverse engineering and computer forensics.
It helps recognizing common functions in compiled binaries and determining libraries they are using.
lscan uses FLIRT (Fast Library Identification and Recognition Technology) signatures to perform library identification.

'''
__author__ = "Marouene Boubakri"
__copyright__ = "Copyright 2016, Semester Project"
__version__ = "0.5"
__email__ = "marouene.boubakri@eurecom.fr"
__status__ = "Development"

import struct
import io
import zlib
import cStringIO
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.common.exceptions import ELFError
import optparse
import os
import re
import pefile

# max function name length
MAX_FLIRT_FUNCTION_NAME = 1024
# architecture flags
ARCH = [
    "386",
    "Z80",
    "I860",
    "8051",
    "TMS",
    "6502",
    "PDP",
    "68K",
    "JAVA",
    "6800",
    "ST7",
    "MC6812",
    "MIPS",
    "ARM",
    "TMSC6",
    "PPC",
    "80196",
    "Z8",
    "SH",
    "NET",
    "AVR",
    "H8",
    "PIC",
    "SPARC",
    "ALPHA",
    "HPPA",
    "H8500",
    "TRICORE",
    "DSP56K",
    "C166",
    "ST20",
    "IA64",
    "I960",
    "F2MC",
    "TMS320C54",
    "TMS320C55",
    "TRIMEDIA",
    "M32R",
    "NEC_78K0",
    "NEC_78K0S",
    "M740",
    "M7700",
    "ST9",
    "FR",
    "MC6816",
    "M7900",
    "TMS320C3",
    "KR1878",
    "AD218X",
    "OAKDSP",
    "TLCS900",
    "C39",
    "CR16",
    "MN102L00",
    "TMS320C1X",
    "NEC_V850X",
    "SCR_ADPT",
    "EBC",
    "MSP430",
    "SPU",
    "DALVIK"]
# file types flags
FILE_TYPE = {
    "DOSEXE(OLD)": 0x1,
    "DOSCOM(OLD)": 0x2,
    "BIN": 0x4,
    "DOSDRV": 0x8,
    "NE": 0x10,
    "INTEL_HEX": 0x20,
    "MOS_HEX": 0x40,
    "LX": 0x80,
    "LE": 0x100,
    "NLM": 0x200,
    "COFF": 0x400,
    "PE": 0x800,
    "OMF": 0x1000,
    "SREC": 0x2000,
    "ZIP": 0x4000,
    "OMFLIB": 0x8000,
    "AR": 0x10000,
    "LOADER": 0x20000,
    "ELF": 0x40000,
    "W32RUN": 0x80000,
    "AOUT": 0x100000,
    "PILOT": 0x200000,
    "DOS_EXE": 0x400000,
    "DOS_COM": 0x800000,
    "AIXAR": 0x1000000}
# OS types flags
OS_TYPE = {
    "MSDOS": 0x01,
    "WIN": 0x02,
    "OS/2": 0x04,
    "NETWARE": 0x08,
    "UNIX": 0x10,
    "OTHER": 0x20}
# application types flags
APP_TYPE = {
    "CONSOLE": 0x1,
    "GRAPHICS": 0x2,
    "EXE": 0x4,
    "DLL": 0x8,
    "DRV": 0x10,
    "SINGLE-THREADED": 0x20,
    "MULTI-THREADED": 0x40,
    "16BIT": 0x80,
    "32BIT": 0x100,
     "64BIT": 0x200}
# features flags
FEATURES = {
    "STARTUP": 0x01,
    "CTYPE_CRC": 0x02,
    "2BYTE_CTYPE": 0x04,
    "ALT_CTYPE_CRC": 0x08,
    "COMPRESSED": 0x10}
# parsing flags
PARSE_MORE_PUBLIC_NAMES = 0x1
PARSE_TAIL_BYTES = 0x2
PARSE_REF_FUNCTIONS = 0x4
PARSE_MORE_MODULES_WITH_SAME_CRC = 0x8
PARSE_MORE_MODULES = 0x10
# function flags
# function appears as "d" in dumpsig
FUNCTION_D = 0x1
FUNCTION_LOCAL = 0x2
# function appears as "?" in dumpsig
FUNCTION_Q = 0x4
FUNCTION_UNRESOLVED_COLLISION = 0x08
# stores the identified functions names/offsets
matches = {}


class BinaryFunction:
    name = ""
    offset = 0
    size = 0
    buf = ""


class FlirtHeader:
    magic = ""
    version = 0
    arch = 0
    file_types = 0
    os_types = 0
    app_types = 0
    features = 0
    old_n_fcns = 0
    crc16 = 0
    ctype = ""
    lib_name_len = 0
    ctypes_crc16 = 0
    n_fcns = 0
    pat_size = 0
    lib_name = ""
    num_fcns = 0


class FlirtNode:
    len = 0
    var_mask = 0
    pat_bytes = None
    var_bool_arr = None
    childs = []
    modules = []
    parent = None


class FlirtModule:
    crc_len = 0
    crc16 = 0
    len = 0
    pub_fcns = None
    tail_bytes = None
    ref_fcns = None


class FlirtFunction:
    name = ""
    offset = 0
    neg_offset = 0
    is_loc = False
    is_col = False


class FlirtTailByte:
    offset = 0
    value = 0


class FlirtFlag:
    flags = 0


class BinarySegment:
    offset = 0
    size = 0
    addr = 0


def parse_pe(pefilepath):
    '''Parses a PE executable and return the list of sections,
    the import table and the raw content
    Args:
        pefile (str): path to a pe binary file
    Returns:
        imgbase: image base
        segs: segment list
        funcs: import table
    '''
    funcs = []
    segs = []
    pe =  pefile.PE(pefilepath, fast_load=True)
    try:
        for sec in pe.sections:
            seg = BinarySegment()
            seg.addr = sec.VirtualAddress
            seg.size = sec.SizeOfRawData
            seg.offset = 0
            segs.append(seg)
        #needed ti calculate function address in virtual space
        imgbase = pe.OPTIONAL_HEADER.ImageBase
        #get imports
        '''pe.parse_data_directories()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                fcn = BinaryFunction()
                fcn.name = imp.name
                fcn.offset = hex(imp.address)
                fcn.size = 0
                funcs.append(fcn)
        '''
    except pefile.PEFormatError:
        sys.stderr.write('Unable to parse PE file')
        sys.exit(1)

    return imgbase, segs, funcs


def parse_elf(elffile):
    '''Parses an ELF executable and return the image base, list of sections,
    the symbol table
    Args:
        elfffile (str): path to an ELF file
    Returns:
        imgbase: image base
        segs: binary segments list
        funcs: binary functions list from symbol table
    '''
    funcs = []
    segs = []
    #imgbase not needed here, function's virtual address is calculated based on segments(address, offset, size)
    imgbase = 0
    try:
        with open(elffile, 'rb') as f:
            elffile = ELFFile(f)
            sec = elffile.get_section_by_name('.symtab')
            if not sec:
                sys.stderr.write("No symbol table found bin binary\n")
            '''if isinstance(sec, SymbolTableSection):
                for i in range(1, sec.num_symbols() + 1):
                    if sec.get_symbol(i)["st_info"]["type"] == "STT_FUNC":
                        fcn = BinaryFunction()
                        fcn.name = sec.get_symbol(i).name
                        fcn.offset = sec.get_symbol(i)["st_value"]
                        fcn.size = sec.get_symbol(i)["st_size"]
                        funcs.append(fcn)
            '''
            f.seek(0)
            for segment in elffile.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    seg = BinarySegment()
                    seg.addr = segment['p_vaddr']
                    seg.size = segment['p_filesz']
                    seg.offset = segment['p_offset']
                    segs.append(seg)
    except ELFError:
        sys.stderr.write('Unable to parse ELF file')
        sys.exit(1)
    return imgbase, segs, funcs




def parse_binary_file(binfile):
    fd = open(binfile, 'rb')
    raw = fd.read()
    fd.close()
    if raw[:4] == b'\x7f\x45\x4c\x46':
        imgbase, segs, funcs = parse_elf(binfile)
        format = 'ELF'
    elif raw[:2] == b'\x4d\x5a':
        imgbase, segs, funcs = parse_pe(binfile)
        format = 'PE'
    else:
        sys.stderr.write('Binary file not supported')
        sys.exit(1)
    return raw, format, imgbase, segs, funcs



def next_byte(buf):
    '''Read one byte from a flirt signature file'''
    byte = struct.unpack("B", buf.read(1))[0]
    if byte != '':
        return byte
    return 0

def next_short (buf):
    '''Read a short value from a flirt signature file'''
    val = (next_byte(buf) << 8)
    val += next_byte(buf)
    return val

def next_word (buf):
    '''Read a word value from a flirt signature file'''
    val = (next_short (buf) << 16)
    val += next_short (buf)
    return val

def next_multibytes (buf):
    '''Read multi-bytes from a flirt signature file (up to 5 bytes)'''
    byte = next_byte(buf)
    if (byte & 0x80) != 0x80:
        return byte
    if (byte & 0xc0) != 0xc0:
        return ((byte & 0x7f) << 8) + next_byte(buf)
    if (byte & 0xe0) != 0xe0:
        byte = ((byte & 0x3f) << 24) + ( next_byte(buf) << 16)
        byte += next_short(buf)
        return byte
    return next_word(buf)

def next_max2bytes(buf):
    '''Read max 2 bytes from a flirt signature file'''
    byte = next_byte(buf)
    if byte & 0x80:
        return ((byte & 0x7f) << 8) + next_byte(buf)
    return byte

def parse_node_length(node, buf):
    '''parse node length. node length is the pattern size of the node'''
    node.len = next_byte(buf)
    return node

def parse_node_variant_mask(node, buf):
    '''parse the mask defining the variant bytes'''
    if node.len < 0x10:
        node.var_mask = next_max2bytes(buf)
    elif node.len <= 0x20:
        node.var_mask = next_multibytes(buf)
    elif node.len <= 0x40:
        node.var_mask = (next_multibytes(buf) << 32)+ next_multibytes(buf)

def parse_node_bytes(node, buf):
    '''parse node bytes and variant bytes'''
    cur_mask_bit = 1 << (node.len - 1)
    node.var_bool_arr = []
    node.pat_bytes = []
    for i in range(node.len):
        node.var_bool_arr.append(True if (node.var_mask & cur_mask_bit) else False)
        if node.var_mask & cur_mask_bit:
            node.pat_bytes.append(0x00)
        else:
            node.pat_bytes.append(next_byte(buf))
        cur_mask_bit >>= 1


def parse_module_public_functions(module, buf, flags, header):
    '''parses module public functions.
    function list is added to the module
    Args:
        module (:obj:`FlirtModule`): current module being parsed by parse_leaf() function
        flags (:obj:`FlirtFlag`): parsing flags
        header (:obj:`FlirtHeader`): parsed header of the signature file
    '''
    # initialize module's public functions list
    module.pub_fcns = []
    offset = 0
    while True:
        fcn = FlirtFunction()
        # parse function offset.
        # if flirt signature version >= 9 parse up to 5 bytes.
        # else parse 2 bytes
        if  header.version >= 9 :
            offset += next_multibytes(buf)
        else:
            offset += next_max2bytes(buf)
        fcn.offset = offset
        cur_byte = next_byte(buf)
        # current byte is a parsing flag
        if cur_byte < 0x20:
            # is function local ?
            if cur_byte & FUNCTION_LOCAL :
                fcn.is_loc = True
            # is it an unresolved collision ?
            if cur_byte & FUNCTION_UNRESOLVED_COLLISION :
                fcn.is_col = True
            if (cur_byte & FUNCTION_D) or (cur_byte & FUNCTION_Q):
                print "investig. flag of pub name..."
            cur_byte = next_byte(buf)
        for i in range(MAX_FLIRT_FUNCTION_NAME):
            if cur_byte < 0x20:
                break
            # current byte is part of the function name
            fcn.name+= chr(cur_byte)
            cur_byte = next_byte(buf)
        # current function's name is too long
        if i == MAX_FLIRT_FUNCTION_NAME:
            # print "Function name too long"
            break
        # parsing flag
        flags.flags = cur_byte
        # append the parsed function to the current module
        module.pub_fcns.append(fcn)
        # increment functions number
        header.num_fcns+=1
        # parse more public functions ?
        if flags.flags & PARSE_MORE_PUBLIC_NAMES == 0:
            break

def parse_module_tail_bytes (module, buf, header):
    '''parses module tail bytes.
    tail bytes list is added to the module
    Args:
        module (:obj:`FlirtModule`): current module being parsed by parse_leaf() function
        buf (str): signature file's raw content
        header (:obj:`FlirtHeader`): parsed header of the signature file
    '''
    # initialize module's tail bytes list
    module.tail_bytes = []
    # how many tail bytes ?
    # assume that we have 1 tail byte if flirt signature version < 8
    if  header.version >= 8 :
        tail_bytes_nbr = next_byte (buf)
    else:
        tail_bytes_nbr = 1
    for i in range(tail_bytes_nbr):
        tail_byte = FlirtTailByte()
        # parse tail byte offset
        if header.version >= 9:
            tail_byte.offset = next_multibytes(buf)
        else:
            tail_byte.offset = next_max2bytes(buf)
        # parse tail byte value
        tail_byte.value = next_byte(buf)
        # add tail bytes to the current module
        module.tail_bytes.append(tail_byte)

def parse_module_referenced_functions(module, buf, header):
    '''parses module referenced functions.
    referenced functions list is added to the module
    Args:
        module (:obj:`FlirtModule`): current module being parsed by parse_leaf() function
        buf (str): signature file's raw content
        header (:obj:`FlirtHeader`): parsed header of the signature file
    '''
    # initialize module's referenced functions list
    module.ref_fcns = []
    # how many referenced functions ?
    # assume that we have 1 referenced function if flirt signature version < 8
    if header.version >= 8 :
        ref_fcn_nbr = next_byte(buf)
    else:
        ref_fcn_nbr = 1
    for i in range(ref_fcn_nbr):
        ref_fcn = FlirtFunction()
        # parse referenced function offset
        if header.version >= 9 :
            ref_fcn.offset = next_multibytes(buf)
        else:
            ref_fcn.offset = next_max2bytes(buf)
            # parse referenced function's name length
        ref_fcn_name_len = next_byte(buf)
        if ref_fcn_name_len == 0 :
            ref_fcn_name_len = next_multibytes(buf)
        for i in range(ref_fcn_name_len):
            ref_fcn.name += chr(next_byte(buf))
        # if function name is null terminated then the offset is negative
        if ref_fcn.name[ref_fcn_name_len-1] == 0:
            ref_fcn.neg_offset = True
        # append the parsed referenced function to the current module
        module.ref_fcns.append(ref_fcn)

def parse_leaf (buf, node, header):
    '''parse a flirt signature leaf.
    a leaf has modules with same leading pattern.
    module list is added to the node
    Args:
        buf (str): raw content of the signature file
        node (:obj:`FlirtNode`): current node being parsed
        header (:obj:`FlirtHeader`): parsed header of the signature file
    '''
    # node module list
    node.modules = []
    # parsing flags
    flags = FlirtFlag()
    while True:
        # parse crc length
        crc_len = next_byte(buf)
        # parse crc value
        crc16 = next_short(buf)
        while True:
            module = FlirtModule()
            module.crc_len = crc_len
            module.crc16 = crc16
            # parse module length.
            # If flirt sig version >= 9 read up to 5 bytes
            # else read 2 bytes
            if header.version >= 9:
                module.len = next_multibytes(buf)
            else:
                module.len = next_max2bytes(buf)
            # parse module public functions
            parse_module_public_functions(module, buf, flags, header)
            # parse module tail bytes
            if flags.flags & PARSE_TAIL_BYTES:
                parse_module_tail_bytes(module, buf, header)
            # parse module referenced functions
            if flags.flags & PARSE_REF_FUNCTIONS:
                parse_module_referenced_functions(module, buf, header)
            # append the parsed module to the current node
            node.modules.append(module)
            # parse funtion with same crc
            if flags.flags & PARSE_MORE_MODULES_WITH_SAME_CRC == 0:
                break
        # parse another module
        if flags.flags & PARSE_MORE_MODULES == 0:
            break

def parse_tree(buf, root_node, header):
    '''parse a tree or a sub-tree
    Args:
        buf (str): raw content of the signature file
        root_node (:obj:`FlirtNode`): current node being parsed
        header (:obj:`FlirtHeader`): parsed header of the signature file
    '''
    # How many initial root nodes ?
    tree_nodes = next_multibytes(buf)
    # If it is equal to 0 then it is a leaf. go and parse it
    if tree_nodes == 0:
        parse_leaf(buf, root_node, header)
    root_node.childs = []
    # for each root node
    for i in range(tree_nodes):
        node = FlirtNode()
        # parse node length
        node = parse_node_length(node, buf)
        # parse node variant mask
        parse_node_variant_mask(node, buf)
        # parse node non-variant bytes
        parse_node_bytes(node, buf)
        # assign current node to its parent node
        node.parent = root_node
        # append the current node to parent's nodes
        root_node.childs.append(node)
        # parse children
        parse_tree(buf, node, header)

def dump_node_pattern (node):
    '''Prints node's variant and non-variant bytes'''
    for i in range(node.len):
        if node.var_bool_arr[i]:
            sys.stdout.write("..")
        else:
            sys.stdout.write("%02X"%node.pat_bytes[i])
    print ":"


def ident(indent):
    for i in range(indent):
        print "  ",

def dump_module(module):
    '''Prints module's public functions, tail bytes and referenced functions'''
    sys.stdout.write("%02X %04X %04X"%(module.crc_len, module.crc16, module.len))
    for func in module.pub_fcns:
        if func.is_loc or func.is_col:
            sys.stdout.write("(")
            if func.is_loc:
                sys.stdout.write("l")
            if func.is_col:
                sys.stdout.write("!")
            sys.stdout.write(")")
        sys.stdout.write("%04X:%s"%(func.offset, func.name))
    if module.tail_bytes:
        for tail_byte in module.tail_bytes:
            sys.stdout.write(" (%04X: %02X)"%(tail_byte.offset, tail_byte.value))
    if module.ref_fcns:
        print " (REF ",
        for ref_func in module.ref_fcns:
            sys.stdout.write("%04X: %s"%(ref_func.offset, ref_func.name))
        sys.stdout.write(")")
    print " "

def dump_node(node,indent = 0):
    '''dump a flirt signature node, the output is the same as the dumpsig command output'''
    if node.pat_bytes is not None:
        ident(indent)
        dump_node_pattern(node)
    if len(node.childs):
        for child in node.childs:
            dump_node(child, indent + 1)
    elif len(node.modules):
        i = 0
        for module in node.modules:
            ident (indent + 1)
            print "%d."%i,
            dump_module(module)
            i+=1

def parse_flg_str(flag, value, str):
    if flag & value:
        return str
    return ""

def dump_header(header):
    '''Prints signature file header
    Args:
        header (:obj:`FlirtHeader`): a parsed signature file header, use parse_signature_file() function to parse the header
    '''
    print "lib: %s"%header.lib_name
    print "magic: %s"%header.magic
    print "version: %d"%header.version
    print "arch: %s"%ARCH[header.arch]
    file_types = ""
    for file_type in FILE_TYPE:
        file_types+= parse_flg_str(FILE_TYPE[file_type],header.file_types, file_type)+" "
    print "file type: %s"%file_types
    os_types = ""
    for os_type in OS_TYPE:
        os_types+= parse_flg_str(OS_TYPE[os_type],header.os_types, os_type)+" "
    print "os type: %s"%os_types

    app_types = ""
    for app_type in APP_TYPE:
        app_types+= parse_flg_str(APP_TYPE[app_type],header.app_types, app_type)+" "
    print "app type: %s"%app_types
    features = ""
    for feature in FEATURES:
        features+= parse_flg_str(FEATURES[feature],header.features, feature)+" "
    print "features: %s"%features
    print "old n functions: %04x"%header.old_n_fcns
    print "crc16: %04x"%header.crc16
    print "ctype: %s"%header.ctype
    print "lib name len: %s"%header.lib_name_length
    print "ctypes crc16: %04x"%header.ctypes_crc16

def parse_signature_file(file):
    '''Parse a flirt signature file
    Args:
        path (str): path to a .sig signature file
    Returns:
        root_node: (:obj:`FlirtNode`): the root node
        header: (:obj:`FlirtHeader`): parsed signature file header
    '''
    sigfile = open(file, 'rb')
    # parse the header
    header = FlirtHeader()
    buf = io.BytesIO(sigfile.read())
    buf.seek(0)
    header.magic = buf.read(6)
    if header.magic != "IDASGN":
        print 'Not a FLIRT signature'
        return
    header.version = next_byte(buf)
    header.arch = next_byte(buf)
    header.file_types = next_word(buf)
    header.os_types = next_short(buf)
    header.app_types = next_short(buf)
    header.features = next_short(buf)
    header.old_n_fcns = next_short(buf)
    header.crc16 = next_short(buf)
    header.ctype = buf.read(12)
    header.lib_name_length = next_byte(buf)
    header.ctypes_crc16 = next_short(buf)
    if header.version >= 6:
        header.n_fcns = next_word(buf)
    if header.version >= 8:
        header.pat_size = next_short(buf)
    header.lib_name = buf.read(header.lib_name_length)
    # read raw content
    buf = buf.read(sigfile.tell() - buf.tell())
    # if the signature file is compressed then decompress it
    if header.features & 0x10:
        if header.version == 5 :
            print 'Compression is not supported in version 5'
            return
        z = zlib.decompressobj()
        buf = z.decompress(buf)
    buf = cStringIO.StringIO(buf)
    buf.seek(0)
    # create the root node
    root_node = FlirtNode()
    # start parsing
    parse_tree(buf, root_node, header)
    return root_node, header

def crc16(buf, len):
    '''Compute the crc16 of a buffer content with given length
    Args:
        buf (str): buffer
        len(int): buffer length
    Returns:
        crc: crc16 value
    '''
    poly = 0x8408
    reg = 0xffff
    i = 0
    while i < len:
        byte = buf[i]
        mask = 0x01
        while mask < 0x100:
            lowbit = reg & 1
            reg >>= 1
            if ord(byte) & mask:
                lowbit ^= 1
            mask <<= 1
            if lowbit:
                reg ^= poly
        i+=1
    reg ^= 0xffff
    crc = chr(reg & 0xff) + chr(reg >> 8)
    return int(crc.encode("hex"),16)


def node_compare_pattern(node, buf,debug=False):
    '''compare node variant and non-variant bytes to a given buffer
    Args:
        node (:obj:`FlirtNode`): a node
        buf (str): binary file raw content
        debug (bool): Prints debugging information
    '''
    for i in range(node.len):
        if i >= len(buf):
            break
        if not node.var_bool_arr[i]:
            if i < node.len and node.pat_bytes[i] != ord(buf[i]):
                return False
    return True

def node_compare_buffer(node, buf, fcn, debug=False):
    if node_compare_pattern(node, buf):
        if node.childs:
            for child in node.childs:
                if node_compare_buffer(child, buf[node.len:],fcn, debug):
                    return True
        elif node.modules:
            for module in node.modules:
                if module_compare_buffer(module, fcn, fcn.buf, debug):
                    return True
    return False


def identify_functions(node, buf, debug=False):
    '''Searches inside a binary content, bytes that match the current node pattern.
    Args:
        node (:obj:`FlirtNode`): root node or a child node from signature file
        buf (str): binary raw content
        debug (bool): set to True to print debug information
    '''
    # if the current node has children
    if len(node.childs):
        for child in node.childs:
            identify_functions(child, buf, debug)
    # if the current node has modules
    elif len(node.modules):
        pattern = []
        variant = []
        nnode = node
        while nnode:
            if nnode.pat_bytes:
                pattern = nnode.pat_bytes + pattern
                variant = nnode.var_bool_arr + variant
            nnode = nnode.parent
        # build regex expression for non-variant and variant pattern
        re_pat = b""
        for i in range(len(pattern)):
            if variant[i]:
                re_pat+=b"(.)"
            else:
                re_pat+=re.escape(chr(pattern[i]))
            # compile the regex
        regex = re.compile(re_pat, re.DOTALL+re.MULTILINE)
        # search inside the binary for bytes that match the current node pattern
        matchs = regex.finditer(buf)
        for match in matchs:
            # We found a match, let's see if the current offset of the binary is the offset of a known funtion
            for module in node.modules:
                #if module.crc_len == 0:
                #    break
                # compute the crc value of the buffer starting from the function offset+32 to crc length
                bufcrc16 = crc16(buf[match.start()+32:match.start()+32+module.crc_len], module.crc_len)
                if bufcrc16 != module.crc16:
                    break
                # we have the same crc, let's see if the module has tail bytes and try to match them against the current buffer
                if module.tail_bytes:
                    for tail_byte in module.tail_bytes:
                        if ord(buf[match.start()+ 32 + module.crc_len + tail_byte.offset]) == tail_byte.value:
                            # Tail bytes are equal, great, the buffer belongs to a known module so let's read function details from the module and append them to the final result
                            for ffcn in module.pub_fcns:
                                # matches[hex(ffcn.offset+match.start())] = ffcn.name
                                matches[ffcn.name] = hex(ffcn.offset+match.start())
                            break
                if module.ref_fcns:
                    for ref_fcn in module.ref_fcns:
                        opcode = ord(buf[match.start()+ ref_fcn.offset-1])
                        '''
                        opcode = 0xe8 = CALL, opcode = 0xe9 = JMP ...
                        At this level we must be aware of the binary target architecture to parse the refernced function address.
                        Since lscan apply the signature on raw binary content, handling refernced functions is
                        '''
                # great the buffer belongs to a known module so let's read function details from the module and append them to the final result
                for ffcn in module.pub_fcns:
                    if True:
                        # matches[hex(ffcn.offset+match.start())] = ffcn.name
                        matches[ffcn.name] = hex(ffcn.offset+match.start())


def lscan(sigfile, binfile, debug = False, dump = False):
    '''
    This is the entrypoint. Match a binary file against a signature file
    Args:
        sigfile    (str)- path to signature file
        binfile    (str)- path to binary file
        debug (bool)- set to True the function prints function offset/name pair
    '''
    sigfiles = []
    if os.path.isfile(sigfile):
        sigfiles.append(sigfile)
    elif os.path.isdir(sigfile):
        sigfiles.extend([os.path.join(sigfile,fn) for fn in next(os.walk(sigfile))[2]])
    # read the binary file
    buf, format, imgbase, segs, funcs =  parse_binary_file(binfile)
    # print "Total functions in binary %d"%len(fcns)
    for sigf in sigfiles:
        matches.clear()
        # parse a signature file
        root_node, header = parse_signature_file(sigf)
        if dump:
            dump_header(header)
            dump_node(root_node)
        # do the job
        identify_functions(root_node, buf, debug)
        print "%s %d/%d (%s%%)"%(sigf, len(matches), header.num_fcns, "{:.2f}".format(100 * float(len(matches))/float(header.num_fcns)))
        # print the result
        if debug:
            for fn in matches:
                if format == 'ELF':
                    for seg in segs:
                        if seg.addr + int(matches[fn],16) < seg.addr + seg.size:
                            print "\t0x%x: %s"%(seg.addr + int(matches[fn],16), fn)
                            break
                elif format == 'PE':
                    print "\t0x%x: %s"%(imgbase + int(matches[fn],16), fn)

if __name__ == "__main__":

    pars = optparse.OptionParser()

    pars.add_option('-v', '--versbose',action="store_true", dest="verbose", help="Verbose mode", default=False)
    pars.add_option('-s', '--sig',action="store", dest="sigfile", type="string", help="Signature file",default=None)
    pars.add_option('-S', '--sigs',action="store", type="string", dest="sigdir", help="Signature folder",default=None)
    pars.add_option('-f', '--file',action="store", type="string", dest="binfile", help="ELF file",default=None)
    pars.add_option('-d', '--dump',action="store_true", dest="dump", help="Dump signature filre",default=None)

    opts, args = pars.parse_args()

    if not opts.binfile:
        pars.error('No binary file given')

    if not opts.sigfile and not opts.sigdir:
        pars.error('Signature File/Folder not given')

    if opts.sigdir and not os.path.isdir(opts.sigdir):
        pars.error('%s is not a directory'%opts.sigdir)
    if opts.sigfile and os.path.isdir(opts.sigfile):
        pars.error('%s is a directory'%opts.sigfile)

    lscan(opts.sigdir if opts.sigdir else opts.sigfile, opts.binfile, opts.verbose, opts.dump)





