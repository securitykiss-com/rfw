

REST API
--------

-  to modify INPUT chain:
   PUT /input/input\_iface/src\_ip[?wait=true[&expire=n\_sec]]
   DELETE /input/input\_iface/src\_ip[?wait=true]

TODO add wait=true options in description

-  | to modify OUTPUT chain: PUT
   /output/output\_iface/dst\_ip[?expire=n\_sec]
   | DELETE /output/output\_iface/dst\_ip

-  | to modify FORWARD chain: PUT
   /forward/input\_iface[/src\_ip[/output\_iface[/dst\_ip[?expire=n\_sec]]]]
   | DELETE /forward/input\_iface[/src\_ip[/output\_iface[/dst\_ip]]]

-  | to list rules: GET /chain[/iface]
   | TODO allow various formats of rules list

-  return help info for client. Response should include server ip, port,
   and relevant rfw configuration details GET /

expire parameter is valid only for PUT requests




| 0.0.0.0 can only be used in FORWARD chain to signal any IP
| iface without number like ppp means ppp+ in iptables parlance
| any in place of interface means any interface

PUT means for iptables: - for INPUT chain: insert the rule matching packets with specified source IP and input interface and apply DROP target - for OUTPUT chain: insert the rule matching packets with specified destination IP and output interface and apply DROP target

| DELETE means: DELETE the rule
| PUT checks for duplicates first so subsequent updates do not add new rules, but it is not purely idempotent since it may update the expiry timeout

Design choices
--------------

Note that HTTPS is not the perfect choice protocol here since by default it authenticates the server while we need to authenticate the client.  Anyway we want to use standard protocols here so we stick to the SSL + basic authentication scheme commonly used on the web. SSL authenticates the server with certificates while shared username + password authenticates the client. Client certificates in HTTPS are possible but not all client libraries support it; also it would complicate deployment.


