#!/bin/bash
rm fido2-sprinboot*

echo "Generating Sprinbgoot key"
openssl genrsa -passout file:pass.txt -des3 -out fido2-springboot.key 4096
echo "Generating Sprinbgoot CSR" 
openssl req -verbose -new -key fido2-springboot.key -out fido2-springboot.csr -sha256 -subj "/C=IE/ST=Leinster/L=Dublin/O=ESS/OU=FIDO2 ESS/CN=yourdomain.here" -passin file:pass.txt

echo "Signing Sprinbgoot CSR" 
openssl ca -out fido2-springboot.pem -keyfile fido2.CA.key -passin file:pass.txt -infiles fido2-springboot.csr 

echo "Exporting as p12"
openssl pkcs12 -export -inkey fido2-springboot.key -in fido2-springboot.pem -out fido2-springboot.p12 -passin file:pass.txt -passout file:pass.txt

