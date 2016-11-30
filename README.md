# lscan
lscan is a tool which identifying library in statically linked/stripped binaries.
The tool is useful for the reverse engineering and computer forensics.
It helps recognizing common functions in compiled binaries and determining libraries they are using.
lscan uses FLIRT (Fast Library Identification and Recognition Technology) signatures to perform library identification.

## Install


If you want to use lscan, you have to install [pyelftools](https://github.com/eliben/pyelftools) and [pefile](https://github.com/erocarrera/pefile) first.

After pyelftools and pefile are installed, lscan can be used as a standalone tool

> $python lscan.py  [-h] [-f BINFILE] [-s SIGFILE] [-S SIGDIR] [-v]


## Usage


$lscan.py 

Options:

>  -h, --help     show this help message and exit  
>  -v, --versbose        Verbose mode  
>  -s SIGFILE, --sig=SIGFILE  
>                        Signature file						
>  -S SIGDIR, --sigs=SIGDIR  
>                        Signature folder						
>  -f BINFILE, --file=BINFILE  
>                        ELF file

### Example:

> $python lscan.py -S i386/sig -f i386/bin/bin-libc-2.23

> $python lscan.py -s i386/sig/libpthread-2.23.sig -f i386/bin/bin-libpthread-2.23 -v

> $python lscan.py -f i386/win32/bin/bin-libcmt.exe -s i386/win32/sig/msvcmrt.sig



## Demo
[Reverse Engineer a stripped binary with lscan and IDApro](https://github.com/maroueneboubakri/lscan/wiki/Reverse-Engineer-a-stripped-binary-with-lscan-and-IDApro). 


## Updating sig database

To generate sig files and add them to lscan fig database you need [Hex-Rays flair toolkit](https://www.hex-rays.com/products/ida/support/ida/flair69.zip). 

Generate the pat file 

> $./pelf /usr/lib/libc.a libc.pat

Generate the sig file from the pat file

> $./sigmake libc.pat libc.sig

Optionally Use -n parameter to specify the library name.

Collisions may occurs while generating the sig file. In this case a libc.exc file will be created. To resolve the conflicts you must edit the .exc and add '+' at the start of the line to keep a module or '-' if you are not sure about the selection. Do nothing if you want to exclue all the modules. After resolving the conflicts run the above command again. Finnaly copy the libc.sig file to lscan's sig folder.

For coff lib format use pcf instead of pelf

> $./pcf libcmt.lib libcmt.pat

## Changelog

**Version 0.5 (2016-06-26)**
- Added support to PE binaries


**Version 0.4 (2016-06-19)**
- Bug fix: handling tail bytes, type mismatch in comparison
- Bug fix: Regex, search method replaced by finditer method to iterate through all node pattern matches
- Bug fix: handling tail bytes, iterate through all functions in module having tail bytes
- Handling modules with crc length = 0 and crc = 0 espacially for small functions


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


## Authors
- Marouene Boubakri <[marouene.boubakri@eurecom.fr](mailto:marouene.boubakri@eurecom.fr)>
