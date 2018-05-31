#!/bin/bash
rm fido2*
rm -r demoCA
mkdir demoCA
mkdir demoCA/newcerts
touch demoCA/index.txt
echo deadbeef > demoCA/serial
echo 123456 > pass.txt
echo "Genrating CA Key"
openssl genrsa -passout file:pass.txt -des3 -out fido2.CA.key 4096 
echo "Generating CA CSR"
openssl req -verbose -new -key fido2.CA.key -out fido2.CA.csr -sha256 -subj "/C=IE/ST=Leinster/L=Dublin/O=ESS/OU=FIDO2 ESS/CN=Dawid CA" -passin file:pass.txt
echo "Signing CA CSR"
openssl ca -verbose -extensions v3_ca -keyfile fido2.CA.key -out fido2.CA.signed.crt -selfsign -passin file:pass.txt -md sha256 -enddate 330630235959Z -infiles fido2.CA.csr
cp demoCA/newcerts/DEADBEEF.pem demoCA/cacert.pem

#Add this cert to Trusted Authorities list on your browser