#!/bin/bash
for lib in ./*.a
do
    libn=`basename "$lib"`
    libn=${libn::-2}
    pelf "$lib" "$libn.pat"    
    sigmake "$libn.pat" "$libn.sig"
    sed -i '/^;/ d' "$libn.exc"
    sigmake "$libn.pat" "$libn.sig"
done
