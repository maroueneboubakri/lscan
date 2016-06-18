cd lscan/bin/src
mkdir lib
#sudo yum install glibc-static
#wget http://mirror.sfo12.us.leaseweb.net/fedora/linux/updates/testing/24/i386/g/glibc-static-2.23.1-8.fc24.i686.rpm
#sudo rpm -i --force --nodeps  glibc-static-2.23.1-8.fc24.i686.rpm 
sudo yum install glibc-static-2.23.1-8.fc24.i686
gcc ../bin-libc-2.23.c -o ../../bin-libc-2.23 -static -fno-inline-small-functions -m32
gcc ../bin-libm-2.23.c -o ../../bin-libm-2.23 -static -fno-inline-small-functions -m32 -lm
gcc ../bin-libpthread-2.23.c -o ../../bin-libpthread-2.23 -static -fno-inline-small-functions -m32 -lpthread
#wget https://dl.fedoraproject.org/pub/fedora/linux/updates/23/i386/g/glibc-static-2.22-17.fc23.i686.rpm
#sudo rpm -i --force --nodeps glibc-static-2.22-17.fc23.i686.rpm
sudo yum install glibc-static-2.22-17.fc23.i686
gcc ../bin-libc-2.22.c -o ../../bin-libc-2.22 -static -fno-inline-small-functions -m32
gcc ../bin-libm-2.22.c -o ../../bin-libm-2.22 -static -fno-inline-small-functions -lm -m32
gcc ../bin-libpthread-2.22.c -o ../../bin-libpthread-2.22 -static -fno-inline-small-functions -lpthread -m32
#wget http://ftp.riken.jp/Linux/centos/7/updates/x86_64/Packages/glibc-static-2.17-106.el7_2.6.i686.rpm
#sudo rpm -i --force --nodeps glibc-static-2.17-106.el7_2.6.i686.rpm 
sudo yum install glibc-static-2.17-106.el7_2.6.i686.rpm
gcc ../bin-libc-2.17.c -o ../../bin-libc-2.17 -static -fno-inline-small-functions -m32
gcc ../bin-libm-2.17.c -o ../../bin-libm-2.17 -static -fno-inline-small-functions -lm -m32
gcc ../bin-libpthread-2.17.c -o ../../bin-libpthread-2.17 -static -fno-inline-small-functions -lpthread -m32
#sudo yum install zlib-static
#wget http://ftp.gnome.org/mirror/fedora/enchilada/linux/releases/23/Everything/i386/os/Packages/z/zlib-static-1.2.8-9.fc23.i686.rpm
#sudo rpm -i --force --nodeps  zlib-static-1.2.8-9.fc23.i686.rpm 
sudo yum install zlib-static-1.2.8-9.fc23.i686
gcc ../bin-libz-1.2.8.c -o ../../bin-libz-1.2.8 -static -fno-inline-small-functions -m32 -lz
#wget http://195.220.108.108/linux/centos/7.2.1511/os/x86_64/Packages/zlib-static-1.2.7-15.el7.i686.rpm
#sudo rpm -i --force --nodeps zlib-static-1.2.7-15.el7.i686.rpm 
sudo yum install zlib-static-1.2.7-15.el7.i686
gcc ../bin-libz-1.2.7.c -o ../../bin-libz-1.2.7 -static -fno-inline-small-functions -m32 -lz
#wget http://195.220.108.108/linux/centos/6.8/os/i386/Packages/zlib-static-1.2.3-29.el6.i686.rpm
#sudo rpm -i --force --nodeps zlib-static-1.2.3-29.el6.i686.rpm 
sudo yum install zlib-static-1.2.3-29.el6.i686
gcc ../bin-libz-1.2.3.c -o ../../bin-libz-1.2.3 -static -fno-inline-small-functions -m32 -lz

#sudo yum install libxml2-static
#sudo yum install xz-static
#wget http://195.220.108.108/linux/fedora/linux/updates/23/i386/l/libxml2-static-2.9.3-2.fc23.i686.rpm
#sudo rpm -i --force --nodeps libxml2-static-2.9.3-2.fc23.i686.rpm 
sudo yum install libxml2-static-2.9.3-2.fc23.i686
gcc ../bin-libxml2-2.9.3.c -o ../../bin-libxml2-2.9.3 -static -fno-inline-small-functions -m32 -I /usr/include/libxml2/ -lxml2 -lz -lm -llzma
#wget http://195.220.108.108/linux/fedora/linux/releases/23/Everything/i386/os/Packages/l/libxml2-static-2.9.2-7.fc23.i686.rpm
#sudo rpm -i --force --nodeps libxml2-static-2.9.2-7.fc23.i686.rpm 
sudo yum install libxml2-static-2.9.2-7.fc23.i686
gcc ../bin-libxml2-2.9.2.c -o ../../bin-libxml2-2.9.2 -static -fno-inline-small-functions -m32 -I /usr/include/libxml2/ -lxml2 -lz -lm -llzma
#wget http://mirror.centos.org/centos/7/updates/x86_64/Packages/libxml2-static-2.9.1-6.el7_2.2.i686.rpm
#sudo rpm -i --force --nodeps libxml2-static-2.9.1-6.el7_2.2.i686.rpm 
sudo yum install libxml2-static-2.9.1-6.el7_2.2.i686
gcc ../bin-libxml2-2.9.1.c -o ../../bin-libxml2-2.9.1 -static -fno-inline-small-functions -m32 -I /usr/include/libxml2/ -lxml2 -lz -lm -llzma
#wget http://web.mit.edu/kerberos/dist/krb5/1.14/krb5-1.14.2.tar.gz
#tar xzf krb5-1.14.2.tar.gztar xzf krb5-1.14.2.tar.gz
#cd krb5-1.14.2/src
#./configure CFLAGS=-m32 LDFLAGS=-m32 --enable-static --disable-shared
#make
#sudo cp lib/*.a /usr/lib
#sudo yum install krb5-devel-1.6.1-80.el5_11.i386
#sudo yum install openssl-static
#wget http://rpmfind.net/linux/centos/5.11/updates/i386/RPMS/openssl-devel-0.9.8e-40.el5_11.i386.rpm
#sudo rpm -i --force --nodeps openssl-devel-0.9.8e-40.el5_11.i386.rpm 
sudo yum install openssl-devel-0.9.8e-40.el5_11.i386
gcc ../bin-libcrypto-0.9.8e.c -o ../../bin-libcrypto-0.9.8e -static -fno-inline-small-functions -m32 -lcrypto -lz -ldl
gcc ../bin-libssl-0.9.8e.c -o ../../bin-libssl-0.9.8e -static -fno-inline-small-functions -m32 -lssl -lcrypto -lz -ldl -Wl,--unresolved-symbols=ignore-all
#wget http://195.220.108.108/linux/centos/6.8/updates/i386/Packages/openssl-static-1.0.1e-48.el6_8.1.i686.rpm
#sudo rpm -i --force --nodeps openssl-static-1.0.1e-48.el6_8.1.i686.rpm 
sudo yum install openssl-static-1.0.1e-48.el6_8.1.i686
gcc ../bin-libcrypto-1.0.1e.c -o ../../bin-libcrypto-1.0.1e -static -fno-inline-small-functions -m32 -lcrypto -lz -ldl -Wl,--unresolved-symbols=ignore-all
gcc ../bin-libssl-1.0.1e.c -o ../../bin-libssl-1.0.1e -static -fno-inline-small-functions -m32 -lssl -lcrypto -lz -ldl -Wl,--unresolved-symbols=ignore-all
#wget http://195.220.108.108/linux/fedora/linux/updates/23/i386/o/openssl-static-1.0.2h-1.fc23.i686.rpm
sudo yum install openssl-static-1.0.2h-1.fc23.i686
gcc ../bin-libcrypto-1.0.2h.c -o ../../bin-libcrypto-1.0.2h -static -fno-inline-small-functions -m32 -lcrypto -lz -ldl -Wl,--unresolved-symbols=ignore-all
gcc ../bin-libssl-1.0.2h.c -o ../../bin-libssl-1.0.2h -static -fno-inline-small-functions -m32 -lssl -lcrypto -lz -ldl -Wl,--unresolved-symbols=ignore-all
#sudo yum install pcre-static
#wget http://195.220.108.108/linux/centos/7.2.1511/os/x86_64/Packages/pcre-static-8.32-15.el7.i686.rpm
#sudo rpm -i --force --nodeps pcre-static-8.32-15.el7.i686.rpm
sudo yum install pcre-static-8.32-15.el7.i686
gcc ../bin-libpcre-8.32.c -o ../../bin-libpcre-8.32 -static -fno-inline-small-functions -m32 -lpcre -lpthread
#wget http://195.220.108.108/linux/fedora/linux/releases/23/Everything/i386/os/Packages/p/pcre-static-8.37-4.fc23.i686.rpm
#sudo rpm -i --force --nodeps pcre-static-8.37-4.fc23.i686.rpm 
sudo yum install pcre-static-8.37-4.fc23.i686
gcc ../bin-libpcre-8.37.c -o ../../bin-libpcre-8.37 -static -fno-inline-small-functions -m32 -lpcre -lpthread
#wget http://195.220.108.108/linux/fedora/linux/updates/23/i386/p/pcre-static-8.38-7.fc23.i686.rpm
#sudo rpm -i --force --nodeps pcre-static-8.38-7.fc23.i686.rpm
sudo yum install pcre-static-8.38-7.fc23.i686
gcc ../bin-libpcre-8.38.c -o ../../bin-libpcre-8.38 -static -fno-inline-small-functions -m32 -lpcre -lpthread
#sudo yum install glib2-static
#wget http://195.220.108.108/linux/sourceforge/m/ma/magicspecs/apt/3.0/i686/RPMS.g/glib2-static-2.40.0-1mgc30.i686.rpm
#sudo rpm -i --force --nodeps glib2-static-2.40.0-1mgc30.i686.rpm 
sudo yum install glib2-static-2.40.0-1mgc30.i686
gcc ../bin-glib2-2.40.c -o ../../bin-glib2-2.40 -static -fno-inline-small-functions -m32 -I /usr/include/glib-2.0/ -I /usr/lib/glib-2.0/include/ -lglib-2.0 -lpthread
#wget http://195.220.108.108/linux/fedora/linux/updates/22/i386/g/glib2-static-2.44.1-2.fc22.i686.rpm
#sudo rpm -i --force --nodeps glib2-static-2.44.1-2.fc22.i686.rpm 
sudo yum install glib2-static-2.44.1-2.fc22.i686
gcc ../bin-glib2-2.44.c -o ../../bin-glib2-2.44 -static -fno-inline-small-functions -m32 -I /usr/include/glib-2.0/ -I /usr/lib/glib-2.0/include/ -lglib-2.0 -lpthread
#wget http://195.220.108.108/linux/fedora/linux/updates/23/i386/g/glib2-static-2.46.2-2.fc23.i686.rpm
#sudo rpm -i --force --nodeps glib2-static-2.46.2-2.fc23.i686.rpm 
sudo yum install glib2-static-2.46.2-2.fc23.i686
gcc ../bin-glib2-2.46.c -o ../../bin-glib2-2.46 -static -fno-inline-small-functions -m32 -I /usr/include/glib-2.0/ -I /usr/lib/glib-2.0/include/ -lglib-2.0 -lpthread
