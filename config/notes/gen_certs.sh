#!/usr/bin/env sh

# Here are notes on creating certs and CA

#################################
# 1. Self-signed cert
#################################
# https://devcenter.heroku.com/articles/ssl-certificate-self

# Generate private key and certificate signing request
openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
openssl rsa -passin pass:x -in server.pass.key -out server.key
rm server.pass.key
openssl req -new -key server.key -out server.csr

# Generate self-signed SSL certificate
openssl x509 -req -days 3653 -in server.csr -signkey server.key -out server.crt



#################################
# 2. Create CA and sign certs
#################################
# See http://blog.didierstevens.com/2008/12/30/howto-make-your-own-cert-with-openssl/

# generate a 4096-bit long RSA key for the root CA if does not exist
openssl genrsa -out ca.key 4096

# create our self-signed root CA certificate ca.crt; you’ll need to provide an identity for your root CA
openssl req -new -x509 -days 1826 -key ca.key -out ca.crt
# give it informative common name CN

# create our intermediate CA that will be used for the actual signing. First, generate the key
openssl genrsa -out ia.key 4096

# then, request a certificate for this subordinate CA
openssl req -new -key ia.key -out ia.csr
# give it IP address CN

#process the request for the subordinate CA certificate and get it signed by the root CA.
openssl x509 -req -days 730 -in ia.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out ia.crt


# Then the client needs to import only a single CA even when every server has a different cert what simplifies deployment.
