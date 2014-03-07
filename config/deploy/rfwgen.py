# usage:
# rfwgen <server_ip>

import subprocess, os, re, sys, time

def usage():
    usage = "rfwgen - key and cert generator for rfw\n\nusage: rfwgen server_ip"
    return usage


def validate_ip(ip):
     """Check if the IP address has correct format.
     return validated and trimmed IP address as string or False if not valid
     """
     if not ip:
         return False
     ip = ip.strip()
     m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
     if m:
         a1, a2, a3, a4 = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
         if a1<256 and a2<256 and a3<256 and a4<256:
             ip_canon = "{}.{}.{}.{}".format(a1, a2, a3, a4)
             return ip_canon
     return False





def call(lcmd):
    try:
        out = subprocess.check_output(lcmd, stderr=subprocess.STDOUT)
        return out
    except subprocess.CalledProcessError, e:
        print("Error code {} returned when called '{}'. Command output: '{}'".format(e.returncode, e.cmd, e.output))
        raise e

if __name__ == '__main__':

    if len(sys.argv) != 2:
        print usage()
        sys.exit(-1)
    server_ip = validate_ip(sys.argv[1])
    if not server_ip:
        print usage()
        sys.exit(-1)

    # set umask


    server_dir = 'server_{}'.format(server_ip)
    ca_key = 'offline/ca.key'
    ca_crt = 'client/ca.crt'
    server_key = os.path.join(server_dir, 'server_key')
    server_crt = os.path.join(server_dir, 'server_crt')
    server_csr = os.path.join(server_dir, 'server_csr')

    # check openssl if works
    
    # generate a 4096-bit long RSA key and the root CA if they don't exist
    if not os.path.isfile(ca_key) or not os.path.isfile(ca_crt):
        try:
            os.mkdir('offline')
            os.mkdir('client')
        except OSError, e:
            # ignore the 'dir already exists' error 
            pass
        root_subj = "/C=IE/ST=Universe/L=Internet/O=rfw root CA {}".format(time.strftime("%d-%m-%Y %H:%M:%S"))
        print('Generating rfw root CA in {} and {}'.format(ca_key, ca_crt))
        print(call(['openssl', 'req', '-new', '-newkey', 'rsa:4096', '-days', '7305', '-nodes', '-x509', '-subj', root_subj, '-keyout', ca_key, '-out', ca_crt]))
    else:
        print('Using existing rfw root CA in {} and {}'.format(ca_key, ca_crt))
    

    try:
        os.mkdir(server_dir)
    except OSError, e:
        # ignore the 'dir already exists' error 
        pass

    # create server key
    print(call(['openssl', 'genrsa', '-out', server_key, '2048']))

    # create certificate request for server.crt
    crt_subj = "/C=IE/ST=Universe/L=Internet/O=Server {0}/CN={0}".format(server_ip)
    print(call(['openssl', 'req', '-new', '-subj', crt_subj, '-key', server_key, '-out', server_csr]))
    
    
    # create server certificate signed by the root CA
    print(call(['openssl', 'x509', '-req', '-days', '7305', '-in', server_csr, '-CA', ca_crt, '-CAkey', ca_key, '-set_serial', '01', '-out', server_crt]))

# create self-signed root CA certificate ca.crt; you'll need to provide an identity for your root CA
#openssl req -new -x509 -days 1826 -key ca.key -out ca.crt
# give it informative common name CN

# create our intermediate CA that will be used for the actual signing. First, generate the key
#openssl genrsa -out ia.key 4096

# then, request a certificate for this subordinate CA
#openssl req -new -key ia.key -out ia.csr
# give it IP address CN

#process the request for the subordinate CA certificate and get it signed by the root CA.
#openssl x509 -req -days 730 -in ia.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out ia.crt



