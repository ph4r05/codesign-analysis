#!/bin/bash

for FILE in xx*.cer; do
    REF=${FILE%.cer}
    PAYLOAD=$REF.data.cer
    echo "Verifying and extracting payload $PAYLOAD out of CscaMasterListData file $FILE:"
    echo openssl cms -in $FILE -inform der -noverify -verify -out $PAYLOAD
    openssl cms -in $FILE -inform der -noverify -verify -out $PAYLOAD
    echo "Extracting all certificates from payload $PAYLOAD"
    eval $(openssl asn1parse -in $PAYLOAD -inform der -i|\
           awk "/:d=1/{b=0}
                /:d=1.*SET/{b=1}
                /:d=2/&&b{print}"|\
           sed 's/^ *\([0-9]\+\).*hl= *\([0-9]\+\).*l= *\([0-9]\+\).*/\
                  dd if=$PAYLOAD bs=1 skip=\1 count=$((\2+\3)) 2>\/dev\/null > $REF.\1.cer;\
                  openssl x509 -in $REF.\1.cer -inform der -out $REF.\1.pem -outform pem;\
                  openssl x509 -in $REF.\1.pem -inform pem -noout -text > $REF.\1.txt;/')
done

