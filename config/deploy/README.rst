

# Network interfaces defined by IP to which HTTPS server is binding.
#
# If set to 0.0.0.0 the rfw server binds (listens on) all interfaces.
# Even in such case there is only one valid SSL secured url with single IP.
# It's because rfw does not support Server Name Indication (SNI) which means
# that rfw presents only one SSL certificate for single IP. That IP selected
# while generating the certificate will determine the SSL secured URL.
# While rfw can listen on all available IPs, an attempt to connect to a different IP, 
# will generate 'ssl_error_bad_cert_domain' on client side.
#
# If outward.server is not enabled this option is ignored.



# Then the client needs to import only a single CA even when every server has a different cert what simplifies deployment.

