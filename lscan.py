__author__ = "Marouene Noubakri"
__copyright__ = "Copyright 2016, Semester Project"
__version__ = "0.4"
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

MAX_NAME = 1024
ARCH = ["386","Z80","I860","8051","TMS","6502","PDP","68K","JAVA","6800","ST7","MC6812","MIPS","ARM","TMSC6","PPC","80196","Z8","SH","NET","AVR","H8","PIC","SPARC","ALPHA","HPPA","H8500","TRICORE","DSP56K","C166","ST20","IA64","I960","F2MC","TMS320C54","TMS320C55","TRIMEDIA","M32R","NEC_78K0","NEC_78K0S","M740","M7700","ST9","FR","MC6816","M7900","TMS320C3","KR1878","AD218X","OAKDSP","TLCS900","C39","CR16","MN102L00","TMS320C1X","NEC_V850X","SCR_ADPT","EBC","MSP430","SPU","DALVIK"]
FILE_TYPE = {"DOSEXE(OLD)": 0x1, "DOSCOM(OLD)": 0x2, "BIN": 0x4,"DOSDRV":0x8,"NE":0x10,"INTEL_HEX": 0x20,"MOS_HEX":0x40,"LX":0x80,"LE":0x100,"NLM":0x200,"COFF": 0x400,"PE":0x800,"OMF":0x1000,"SREC": 0x2000,"ZIP": 0x4000,"OMFLIB": 0x8000,"AR": 0x10000,"LOADER": 0x20000,"ELF":0x40000,"W32RUN": 0x80000,"AOUT":0x100000,"PILOT": 0x200000,"DOS_EXE": 0x400000,"DOS_COM": 0x800000,"AIXAR": 0x1000000}
OS_TYPE = {"MSDOS":0x01, "WIN":0x02, "OS/2":0x04, "NETWARE":0x08, "UNIX":0x10, "OTHER":0x20}
APP_TYPE = {"CONSOLE":0x1, "GRAPHICS":0x2, "EXE": 0x4, "DLL":0x8, "DRV":0x10, "SINGLE-THREADED":0x20,"MULTI-THREADED":0x40, "16BIT":0x80, "32BIT":0x100, "64BIT":0x200}
FEATURES = {"STARTUP":0x01, "CTYPE_CRC":0x02, "2BYTE_CTYPE":0x04, "ALT_CTYPE_CRC":0x08, "COMPRESSED":0x10}

matches = {}

class BinaryFunction:
	name = ""
	offset = 0
	size = 0
	buf = ""
	
class Header:
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

class Node:
        len = 0
        var_mask = 0
        pat_bytes = None
        var_bool_arr = None
        childs = []
        modules = []
        parent = None

class Module:
        crc_len = 0
        crc16 = 0
        len = 0
        pub_fcns = None
        tail_bytes = None
        ref_fcns = None

class Function:
        name = ""
        offset = 0
        neg_offset = 0
        is_loc = False
        is_col = False

class Tail:
        offset = 0
        value = 0

class Flag:
                flags = 0


class Segment:
		offset = 0
		size = 0
		addr = 0

def parse_bin_file(filename):
	fcns = []
	segs = []
	try:
		with open(filename, 'rb') as f:
			elffile = ELFFile(f)
			sec = elffile.get_section_by_name('.symtab')
			if not sec:
				sys.stderr.write("No symbol table found bin binary\n")

			if isinstance(sec, SymbolTableSection):
				for i in range(1, sec.num_symbols() + 1):
					if sec.get_symbol(i)["st_info"]["type"] == "STT_FUNC":
						fcn = BinaryFunction()
						fcn.name = sec.get_symbol(i).name
						fcn.offset = sec.get_symbol(i)["st_value"]
						fcn.size = sec.get_symbol(i)["st_size"]
						fcns.append(fcn)			
			f.seek(0)					
			buf = f.read()
			for segment in elffile.iter_segments():
				if segment['p_type'] == 'PT_LOAD':
					seg = Segment()
					seg.addr = segment['p_vaddr']
					seg.size = segment['p_filesz']
					seg.offset = segment['p_offset']
					segs.append(seg)
	except ELFError:	
		sys.stderr.write('Unable to read bin file')
		sys.exit(1)
	return fcns, buf, segs
	
				
def next_byte (buf):
        byte = struct.unpack("B", buf.read(1))[0]
        if byte <> '':
                return byte
        return 0

def next_short (buf):
        byte = (next_byte(buf) << 8)
        byte += next_byte(buf)
        return byte

def next_word (buf):
        byte = (next_short (buf) << 16)
        byte += next_short (buf)
        return byte

def next_mbytes (buf):
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

def next_m2bytes(buf):
        byte = next_byte(buf)
        if byte & 0x80:
                return ((byte & 0x7f) << 8) + next_byte(buf)
        return byte

def parse_nod_len(node, buf):
        node.len = next_byte(buf)
        return node

def parse_nod_vmask(node, buf):
        if node.len < 0x10:
                node.var_mask = next_m2bytes(buf)
        elif node.len <= 0x20:
                node.var_mask = next_mbytes(buf)
        elif node.len <= 0x40:
                node.var_mask = (next_mbytes(buf) << 32)+ next_mbytes(buf)

def parse_nod_bytes(node, buf):
        cur_mask_bit = 1L << (node.len - 1)
        node.var_bool_arr = []
        node.pat_bytes = []
        for i in range(node.len):
                node.var_bool_arr.append(True if (node.var_mask & cur_mask_bit) else False)
                if node.var_mask & cur_mask_bit:
                        node.pat_bytes.append(0x00)
                else:
                        node.pat_bytes.append(next_byte(buf))
                cur_mask_bit >>= 1


def parse_mod_pub_fcn(module, buf, flags, header):
        module.pub_fcns = []
        offset = 0
        while True:
                fcn = Function()
                if  header.version >= 9 :
                        offset += next_mbytes(buf)
                else:
                        offset += next_m2bytes(buf)
                fcn.offset = offset
                cur_byte = next_byte(buf)
                if cur_byte < 0x20:
                        if cur_byte & 0x2 :
                                fcn.is_loc = True
                        if cur_byte & 0x8 :
                                fcn.is_col = True
                        if (cur_byte & 0x01) or (cur_byte & 0x04):
                                print "investig. flag of pub name..."
                        cur_byte = next_byte(buf)
						
                for i in range(MAX_NAME):
                        if cur_byte < 0x20:
                                break
                        fcn.name+= chr(cur_byte)
                        cur_byte = next_byte(buf)

                if i == MAX_NAME:
                        print "Function name too long"
                flags.flags = cur_byte
                module.pub_fcns.append(fcn)
                #print fcn.name
                header.num_fcns+=1
                if flags.flags & 0x1 == 0:
                        break

def parse_mod_tbytes (module, buf, header):
        module.tail_bytes = []

        if  header.version >= 8 :
                tail_bytes_nbr = next_byte (buf)
        else:
                tail_bytes_nbr = 1

        for i in range(tail_bytes_nbr):
                tail_byte = Tail()
                if tail_byte is None:
                        return False

                if header.version >= 9:
                        tail_byte.offset = next_mbytes(buf)
                else:
                        tail_byte.offset = next_m2bytes(buf)

                tail_byte.value = next_byte(buf)
                module.tail_bytes.append(tail_byte)

def parse_mod_ref_fcn(module, buf, header):
        module.ref_fcns = []

        if header.version >= 8 :
                ref_fcn_nbr = next_byte(buf)
        else:
                ref_fcn_nbr = 1

        for i in range(ref_fcn_nbr):
                ref_fcn = Function()

                if header.version >= 9 :
                        ref_fcn.offset = next_mbytes(buf)
                else:
                        ref_fcn.offset = next_m2bytes(buf)

                ref_fcn_name_len = next_byte(buf)

                if ref_fcn_name_len == 0 :
                        ref_fcn_name_len = next_mbytes(buf)

                for i in range(ref_fcn_name_len):
                        ref_fcn.name += chr(next_byte(buf))

                if  ref_fcn.name[ref_fcn_name_len-1] == 0:
                        ref_fcn.neg_offset = True

                module.ref_fcns.append(ref_fcn)

def parse_leaf (buf, node, header):
        node.modules = []
        flags = Flag()
        while True:
                crc_len = next_byte(buf)
                crc16      = next_short(buf)
                while True:
                        module = Module()
                        module.crc_len = crc_len
                        module.crc16      = crc16
                        if header.version >= 9:
                                module.len = next_mbytes(buf)
                        else:
                                module.len = next_m2bytes(buf)
                        parse_mod_pub_fcn(module, buf, flags, header)
                        if flags.flags & 0x2:
                                parse_mod_tbytes(module, buf, header)
                        if flags.flags & 0x4:
                                parse_mod_ref_fcn(module, buf, header)
                        node.modules.append(module)
                        if flags.flags & 0x8 == 0:
                                break
                if  flags.flags & 0x10 == 0:
                        break

def parse_tree(buf, root_node, header):
        tree_nodes = next_mbytes(buf)
        if tree_nodes == 0:
                parse_leaf(buf, root_node, header)

        root_node.childs = []
        for i in range(tree_nodes):
                node = Node()
                node = parse_nod_len(node, buf)
                parse_nod_vmask(node, buf)
                parse_nod_bytes(node, buf)
                node.parent = root_node
                root_node.childs.append(node)
                parse_tree(buf, node, header)

def dump_nod_pat (node):
        for i in range(node.len):
                if node.var_bool_arr[i]:
                        sys.stdout.write("..")
                else:
                        sys.stdout.write("%02X"%node.pat_bytes[i])
        print ":"


def ident (indent):
        for i in range(indent):
                print "  ",

def dump_mod (module):
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

def dump_nod (node,indent = 0):

        if node.pat_bytes is not None:
                ident(indent)
                dump_nod_pat(node)

        if len(node.childs):
                for child in node.childs:
                        dump_nod(child, indent + 1)
        elif len(node.modules):
                i = 0
                for module in node.modules:
                        ident (indent + 1)
                        print "%d."%i,
                        dump_mod(module)
                        i+=1

def parse_flg_str(flag, value, str):
        if flag & value:
                return str
        return ""

def dump_header(header):
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

        sigfile = open(file, 'rb')

        header = Header()
        buf = io.BytesIO(sigfile.read())
        buf.seek(0)
        header.magic = buf.read(6)

        if header.magic != "IDASGN":
                sys.exit('Not a FLIRT signature')

        header.version = struct.unpack("B", buf.read(1))[0]
        header.arch = struct.unpack("B", buf.read(1))[0]
        header.file_types = struct.unpack("I",buf.read(4))[0]
        header.os_types = struct.unpack("H",buf.read(2))[0]
        header.app_types = struct.unpack("H",buf.read(2))[0]
        header.features = struct.unpack("H", buf.read(2))[0]
        header.old_n_fcns = struct.unpack("H", buf.read(2))[0]
        header.crc16 = struct.unpack("H", buf.read(2))[0]
        header.ctype = buf.read(12)
        header.lib_name_length = struct.unpack("B", buf.read(1))[0]
        header.ctypes_crc16 = struct.unpack("H", buf.read(2))[0]

        if header.version >= 6:
                        header.n_fcns = struct.unpack("I",buf.read(4))[0]
        if header.version >= 8:
                        header.pat_size = struct.unpack("H", buf.read(2))[0]

        header.lib_name = buf.read(header.lib_name_length)

        buf = buf.read(sigfile.tell() - buf.tell())

        if header.features & 0x10:
                        if header.version == 5 :
                                sys.exit('Compression is not supported in version 5')
                        #print "Compressed sig file"
                        z = zlib.decompressobj()
                        buf = z.decompress(buf)

        buf = cStringIO.StringIO(buf)
        buf.seek(0)
        root_node = Node()
        parse_tree(buf, root_node, header)
        return root_node, header

def crc16(buf, len):
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

def mod_cmp_buf(module, fcn, buf, debug=False):
	if len(fcn.buf) == 0:
		return False
	
	if len(buf) < 32 + module.crc_len:
		return False
	
	if 32 + module.crc_len < len(buf) and module.crc16 != crc16(buf[32:], module.crc_len):
		return False
	if module.tail_bytes:
		for tail_byte in module.tail_bytes:
			if 32 + module.crc_len + tail_byte.offset < len(buf) and buf[32 + module.crc_len + tail_byte.offset] != tail_byte.value:
				return False
	for ffcn in module.pub_fcns:		
		matches[hex(ffcn.offset+fcn.offset)] = ffcn.name
	
	return True

	
def nod_cmp_pat(node, buf,debug=False):
	for i in range(node.len):
		if i >= len(buf):
			break
		if not node.var_bool_arr[i]:
			if i < node.len and node.pat_bytes[i] != ord(buf[i]):
				return False
	return True
		
def nod_cmp_buf(node, buf, fcn, debug=False):
	if nod_cmp_pat(node, buf):
		if node.childs:
			for child in node.childs:
				if nod_cmp_buf(child, buf[node.len:],fcn, debug):
					return True	
		elif node.modules:
			for module in node.modules:
				if mod_cmp_buf(module, fcn, fcn.buf, debug):
					return True
	return False

	
def nod_cmp_fcns(rnode, fcns, debug=False):	
	for fcn in fcns:
		#if fcn.name != "strlen":
		#	continue
		for child in rnode.childs:
			if nod_cmp_buf(child, fcn.buf, fcn, debug):
				break


def nod_cmp_fcns2(node, buf, debug=False):        
        if len(node.childs):
                for child in node.childs:
                        nod_cmp_fcns2(child, buf, debug)
        elif len(node.modules):
				pattern = []
				variant = []
				nnode = node
				while nnode:
					if nnode.pat_bytes:
						#print nnode.pat_bytes
						pattern = nnode.pat_bytes + pattern
						variant = nnode.var_bool_arr + variant
					#print nnode.pat_bytes
					#print nnode.var_bool_arr
					nnode = nnode.parent
				#print "".join(map(chr, pattern)).encode("hex")
				#print len(variant)
				re_pat = b""
				#print variant
				#print pattern
				for i in range(len(pattern)):
					if variant[i]:
						re_pat+=b"(.)" 
					else:
						re_pat+=re.escape(chr(pattern[i]))				
				'''pat = "".join(map(chr, pattern))
				pat = [ re.escape(p) for p in pat ]
				pat = b"".join(pat)
				'''
				#print re_pat.encode("hex")
				regex = re.compile(re_pat, re.DOTALL+re.MULTILINE)				
				match = regex.search(buf)				
				if match:
					for module in node.modules:
						found = True
						bufcrc16 = crc16(buf[match.start()+32:match.start()+32+module.crc_len], module.crc_len)
						#print "%x %x"%(bufcrc16,module.crc16)
						if bufcrc16 != module.crc16:
							found = False
						if module.tail_bytes:
							for tail_byte in module.tail_bytes:
								if buf[match.start()+ 32 + module.crc_len + tail_byte.offset] != tail_byte.value:
									found = False												
						if found:
							for ffcn in module.pub_fcns:		
								matches[hex(ffcn.offset+match.start())] = ffcn.name						
										
def identify_functions(sigfile, binfile, debug = False):
	sigfiles = []
	if os.path.isfile(sigfile):
		sigfiles.append(sigfile)
	elif os.path.isdir(sigfile):
		sigfiles.extend([os.path.join(sigfile,fn) for fn in next(os.walk(sigfile))[2]])
	
	fcns, buf, segs =  parse_bin_file(binfile)
	'''if len(fcns) == 0:
		sys.exit("No functions loaded from binary")
	'''
	print "Total functions in binary %d"%len(fcns)
	for sigf in sigfiles:
		matches.clear()
        root_node, header = parse_signature_file(sigf)		        
        #dump_nod(sig.root_node)
        nod_cmp_fcns2(root_node, buf, debug)
		#TODO
        if True:
			print "%s %d/%d (%s%%)"%(sigf, len(matches), header.num_fcns, "{:.2f}".format(100 * float(len(matches))/float(header.num_fcns)))
        else:
			print "%s %d"%(sigf, len(matches))
        if debug:
			for offset in matches:
				for seg in segs:
					if seg.addr + int(offset,16) < seg.addr + seg.size:									
						print "\t0x%x: %s"%(seg.addr + int(offset,16), matches[offset])
						break				
	
if __name__ == "__main__":
	
	pars = optparse.OptionParser()

	pars.add_option('-v', '--versbose',action="store_true", dest="verbose", help="Verbose mode", default=False)
	pars.add_option('-s', '--sig',action="store", dest="sigfile", type="string", help="Signature file",default=None)
	pars.add_option('-S', '--sigs',action="store", type="string", dest="sigdir", help="Signature folder",default=None)
	pars.add_option('-f', '--file',action="store", type="string", dest="binfile", help="ELF file",default=None)

	opts, args = pars.parse_args()

	if not opts.binfile:
		pars.error('No ELF file given')
		
	if not opts.sigfile and not opts.sigdir:
		pars.error('Signature File/Folder not given')

	if opts.sigdir and not os.path.isdir(opts.sigdir):
		pars.error('%s is not a directory'%opts.sigdir)
	if opts.sigfile and os.path.isdir(opts.sigfile):
		pars.error('%s is a directory'%opts.sigfile)
	
	identify_functions(opts.sigdir if opts.sigdir else opts.sigfile, opts.binfile, opts.verbose)



