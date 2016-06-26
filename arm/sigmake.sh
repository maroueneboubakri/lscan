#!/bin/bash
mkdir pat
mkdir exc
mkdir sig
for lib in ./lib/*.a
do
    libn=`basename "$lib"`
    libn=${libn::-2}
    pelf "$lib" "$libn.pat"    
    sigmake "$libn.pat" "$libn.sig"
    sed -i '/^;/ d' "$libn.exc"
    sigmake "$libn.pat" "$libn.sig"
done
mv *.sig sig/
mv *.pat pat/
mv *.exc exc/
