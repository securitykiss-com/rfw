rfwgen
======

``rfwgen`` is a tool that generates necessary PKI artifacts for rfw:

- root CA (Certificate Authority)
- server certificate and private key for each server

rfw works with security certificates that are based on IP address (as opposed to prevalent on the web the certificates based on domain name).
Thus it assumes that the server has a static IP and that REST URLs will be addressing it using that IP.

Deployment example
------------------
The typical deployment scenario is a single client (e.g. a central abuse detection and IP reputation system) and multiple rfw servers listening to firewall modification commands::

                                ======================
                                rfw server 11.11.11.11
    ======                      ======================
    client
    ======                      ======================
                                rfw server 22.22.22.22
                                ======================


Using rfwgen 
------------
You need to run ``rfwgen`` for each rfw server while providing their IP addresses::

./rfwgen 11.11.11.11
./rfwgen 22.22.22.22

After running the above commands the folder tree should look like this::

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

``client/ca.crt`` and ``offline/ca.key`` are generated only when ``rfwgen`` runs first time. Folder names indicate where the files should be deployed:

- client - ca.crt should be imported to the client machine (and possibly also to the test HTTP client)
- offline - ca.key used for signing certificates. It should be kept secret, preferrably offline as security of the entire system depends on it
- server_xxx - server.crt and server.key should be deployed to rfw server with rfw.conf options pointing to their locations on the server

Using your own Certificate Authority complicates initial setup but makes it easier later to add new servers.
The client needs to import only a single CA once.
Adding a new server boils down to generating new certificate and deploying it on the server. The client will accept it without any modification on the client side. 

Import root CA in the client
----------------------------

Copy ``client/ca.crt`` to the client machine and then use it in the way depending on the client browser:

**curl client**

ca.crt can be provided as command line parameter with each query.

The complete curl request::

    curl -v --cacert <path_to_ca_crt> --user <username>:<passwd> https://<server_ip>:7393/

for example::

    curl -v --cacert config/deploy/client/ca.crt --user myuser:mypasswd https://11.11.11.11:7393/input/eth0/1.2.3.4

Alternatively, to avoid specifying the path to ca.crt with every request, you can add the CA cert to the existing default CA cert bundle. The default path of the CA bundle used can be changed by running configure with the --with-ca-bundle option pointing out the path of your choice.

You can also generate server certificate for localhost::

    curl -v --cacert config/deploy/client/ca.crt --user myuser:mypasswd https://127.0.0.1:7393/

Please note the numeric IP above. For consistency ``rfwgen`` accepts only IP addresses so you must use 127.0.0.1 instead of localhost.

**Firefox client**

See the `firefox root CA <http://www.securitykiss.com/resources/tutorials/firefox_root_ca/>`_ instruction on SecurityKISS website.


Deploy keys to the server
-------------------------

Let's assume you deploy to the server with IP 11.11.11.11.

Copy ``server_11.11.11.11/server.crt`` and ``server_11.11.11.11/server.key`` for example to ``/etc/rfw/ssl/`` folder on host 11.11.11.11.
Update ``/etc/rfw/rfw.conf`` in order to point to these files::

    outward.server.certfile = /etc/rfw/ssl/server.crt

    outward.server.keyfile = /etc/rfw/ssl/server.key


FAQ
---

**Can I create a certificate for localhost to test rfw locally?**

Yes, but you must use numeric IP: 127.0.0.1 instead of ``localhost``::

    ./rfwgen 127.0.0.1

and the certificate will only be valid if numeric IP is used in the URL.

**Can I create a certificate for multiple IP addresses on the same server?**

|You can create a certificate for every IP of the server but you cannot configure rfw with all of them at the same time.
|rfw accepts only a single certificate - it does not support Server Name Indication (SNI).
|Even though rfw can listen on multiple IPs (when it binds to all network interfaces), the server presents only one fixed certificate for single IP, the same the certificate was generated for.
|An attempt to connect to a different IP, will generate 'ssl_error_bad_cert_domain' on the client side.

