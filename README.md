# lscan
lscan is an IDA PRO FLIRT signature matcher on statically linked/stripped binaries


## Install


If you want to use lscan, you have to install [pyelftools](https://github.com/eliben/pyelftools) first.

After pyelftools is installed, lscan can be used as a standalone tool

> $python lscan.py options


## Usage


$lscan.py 

Options:

  -h, --help     show this help message and exit  
  -v, --versbose        Verbose mode  
  -s SIGFILE, --sig=SIGFILE  
                        Signature file						
  -S SIGDIR, --sigs=SIGDIR  
                        Signature folder						
  -f BINFILE, --file=BINFILE  
                        ELF file

### Example:

> $python sigmatch.py -S sigdb -f test/bin1 -v

> $python sigmatch.py -s sigdb/libcrypt-2.23.sig -f test/bin2 -v



## Changelog

**Version 0.3 (2016-03-28)**
- Support for stripped binary
- Introduced deep match mode
- Better ELF parsing (function offsets)



**Version 0.2 (2016-03-23)**
- Added support for compressed signtaure files
- Added support to FLIRT functions offset
- Load multiple signature files
- More information output (function offset+names)
- Updated the command line layout and help messages



**Version 0.1(2016-03-20)**
- First release

