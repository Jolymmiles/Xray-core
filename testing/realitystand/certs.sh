#!/bin/sh
# certs.sh <dir>: certificate chains shaped like Let's Encrypt's, which
# browsers take as long to verify as real ones: an RSA 4096 root; an RSA
# 2048 intermediate (like R11) over an RSA 2048 leaf, served by nginx and
# HAProxy; an ECDSA P-384 intermediate (like E5) over an ECDSA P-256 leaf,
# served by Caddy, as it gets by default. Browsers and REALITY trust the root.
set -eu
dir=$1
mkdir -p "$dir" && cd "$dir"
openssl req -x509 -newkey rsa:4096 -nodes -keyout root.key -out root.pem -days 3650 -sha256 \
  -subj "/C=US/O=Stand Security Research Group/CN=Stand Root X1" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
intermediate() { # name keyspec cn
  openssl req -newkey $2 -nodes -keyout $1.key -out $1.csr -subj "/C=US/O=Stand Encrypt/CN=$3"
  printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,digitalSignature,keyCertSign,cRLSign\nextendedKeyUsage=serverAuth,clientAuth\nauthorityInfoAccess=caIssuers;URI:http://x1.i.stand-encr.org/\ncrlDistributionPoints=URI:http://x1.c.stand-encr.org/\ncertificatePolicies=2.23.140.1.2.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' > $1.cnf
  openssl x509 -req -in $1.csr -CA root.pem -CAkey root.key -CAcreateserial -out $1.pem -days 1095 -sha256 -extfile $1.cnf
}
intermediate r11 rsa:2048 R11
intermediate e5 "ec -pkeyopt ec_paramgen_curve:P-384" E5
san="DNS:example.test,DNS:*.example.test"
leaf() { # name keyspec issuer extra-key-usage
  openssl req -newkey $2 -nodes -keyout $1.key -out $1.csr -subj "/CN=example.test"
  printf "subjectAltName=$san\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature$4\nextendedKeyUsage=serverAuth,clientAuth\nauthorityInfoAccess=OCSP;URI:http://$3.o.stand-encr.org,caIssuers;URI:http://$3.i.stand-encr.org/\ncertificatePolicies=2.23.140.1.2.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n" > $1.cnf
  openssl x509 -req -in $1.csr -CA $3.pem -CAkey $3.key -CAcreateserial -out $1.pem -days 90 -sha256 -extfile $1.cnf
}
leaf rsa rsa:2048 r11 ",keyEncipherment"
leaf ecdsa "ec -pkeyopt ec_paramgen_curve:P-256" e5 ""
cat rsa.pem r11.pem > rsa-chain.pem
cat ecdsa.pem e5.pem > ecdsa-chain.pem
cat rsa-chain.pem rsa.key > rsa-haproxy.pem
openssl verify -CAfile root.pem -untrusted r11.pem rsa.pem
openssl verify -CAfile root.pem -untrusted e5.pem ecdsa.pem
