rfw works with security certificates generated for IP address (as opposed to more common in the web the certificate for domain name).
Thus it assumes that the server has static IP and that REST URLs will address it using that IP.

rfwgen is a tool that generates necessary PKI artifacts:
- rfw root CA (Certificate Authority)
- server certificate and private key for each server

Deployment example
------------------
Typical deployment scenario is a single client (e.g. a central abuse detection and IP reputation system) and multiple rfw servers listening to firewall modification commands.

                          rfw server 11.11.11.11
client
                          rfw server 22.22.22.22                        


Using rfwgen 
------------
You need to run rfwgen for each rfw server while providing their IP addresses:

./rfwgen 11.11.11.11
./rfwgen 22.22.22.22

After running the above commands the folder tree should look like this:

    .
    ├── client
    │   └── ca.crt
    ├── offline
    │   └── ca.key
    ├── server_11.11.11.11
    │   ├── server.crt
    │   └── server.key
    └── server_22.22.22.22
        ├── server.crt
        └── server.key

client/ca.crt and offline/ca.key are generated only when rfwgen runs first time. Folder names indicate where the files should be deployed:

- client - ca.crt should be imported to the client machine (and possibly also to the test HTTP client)
- offline - ca.key used for signing certificates. It should be kept secret, preferrably offline as security of the entire system depends on it
- server_xxx - server.crt and server.key should be deployed to rfw server with rfw.conf options pointing to their locations on the server

Using own Certificate Authority complicates initial setup but it makes it easier later to add new servers.
The client needs to import only a single CA once.
Adding a new server boils down to generating new certificate and deploying it on the server. The client will accept it without any modification on the client side. 

Import root CA in client
------------------------
curl 

firefox

libraries


Keys deployment
---------------


11.11.11.11

22.22.22.22






#TODO curl with imported root CA




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




