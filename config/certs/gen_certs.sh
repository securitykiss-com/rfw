#!/usr/bin/env sh

# For now we create the self-signed cert as per:
# https://devcenter.heroku.com/articles/ssl-certificate-self
# In the future automate creating single CA and sign certs for every server.
# See http://blog.didierstevens.com/2008/12/30/howto-make-your-own-cert-with-openssl/
# Then the client needs to import only a single CA even when every server has a different cert what simplifies deployment.

# Generate private key and certificate signing request
openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
openssl rsa -passin pass:x -in server.pass.key -out server.key
rm server.pass.key
openssl req -new -key server.key -out server.csr


# Generate SSL certificate
openssl x509 -req -days 3653 -in server.csr -signkey server.key -out server.crt



