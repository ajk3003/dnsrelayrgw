# Custom DNS relay module for use with Realm Gateway software

## Description

This is Python 3 DNS server/relay software for Linux which can be used to test
and facilitate load balancing with multiple Realm Gateway servers running
simultaneously. This program can forward DNS queries towards Realm Gateway
servers either directly from DNS clients or from some public DNS server and
the direct the DNS replies back from the respective Realm Gateway. There is
an option to randomize traffic towards different Realm Gateways if they
are available simultaneously and there is also an option to add DNS ECS client
subnet information to queries if it is not present.

In order to use this software properly, it is recommended that, as an initial
step, one familiarizes himself how the Realm Gateway software works. The Realm
Gateway program and the instructions to install and run it can be
found at:

https://github.com/Aalto5G/RealmGateway


## Dependencies

This is a Python 3 software for Linux so Python 3.5 or newer is required.
For improved performance, the newest stable version of Python 3 should be
used, though. Only additional Python dependency that is required is the version
1.16 (or newer) of dnspython library. This library and the installation
instructions for it are available on:

https://github.com/rthalley/dnspython

The custom DNS relay has tested to work with Ubuntu 16.04 and Ubuntu 18.04.


## Running custom DNS relay software

As a first step to actually utilize custom DNS relay properly, one should run
it in conjunction with 1 or more Realm Gateways protecting some web service
that the DNS client wants to access. When starting the Realm Gateway, the
configuration parameters for it should be noted. The custom DNS relay program
itself takes the following parameters as command line arguments upon the start:
- Server IPv4 address in a.b.c.d form; this is the address the DNS relay
listens for incoming connections
- Server port; this is the port the DNS relay listens for incoming connections
(Note that both the given address and port should be accessible in the system)
- Turn ECS/client subnet information forwarding on/off
- Turn DNS TCP security step on/off
- Turn DNS CNAME security step on/off
- Turn destination Realm Gateway randomization on/off, if multiple Realm
Gateways are available for DNS queries, otherwise the first given Realm Gateway
address/port is used
- Set the Realm Gateway CNAME string component if CNAME security step is used
- Set DNS request timeout in seconds
- Set additional DNS request attempt amount if the first attempt fails
- Address or Addresses (and respective port(s)) for Realm Gateways that
for which the custom DNS relay forwards the DNS queries

IMPORTANT NOTES:
- The ECS forwarding should be generally turned on as Realm Gateway uses this
data to identify the connection between client and DNS query
- At least currently, the TCP security step should be turned off in the Realm
Gateway config. The current version of custom DNS will handle the DNS TCP
queries (ie. the TCP security step) if that is necessary
- If CNAME security is used, it should be enabled both in the Realm Gateway
config and with the custom DNS relay; additionally the leftmost part of
the Realm Gateway parameter "dns-cname-soa" should be given to the custom DNS
relay on start using the "-cnamestr" option. For example if the "dns-cname-soa"
parameter when startign Realm Gateway was "cname.example", the the input for
custom DNS relay would be the string "cname"

More help can be found using the "-h" option when starting the custom DNS relay.
An example input to start the custom DNS relay is below:
```
# python3.7 customDNSv1.py -saddr 192.168.1.5 -sport 53 -tcp yes -cname yes -randrgw yes -cnamestr cname -rgws 192.168.2.5 53 192.168.3.5 53
```
The example here assumes that the given server address and port is available in
the system, and that Realm Gateway is run on the given addresses and ports.
The DNS server component of each Realm Gateway is connected to these
addresses and ports. Additionally, the dns-cname-soa parameter for these Realm
Gateways should be "cname.something".

### Using custom DNS relay with multiple Realm Gateways simultaneously
If multiple Realm Gateways are used at the same time to protect some web
service, there is first a need to configure a source-based routing entity
between the protected service and the Realm Gateways. The basic idea here
(if no nested Realm Gateways are used) is that the protected entity runs
multiple IP addresses for its service where each of these addresses is
connected to a particular Realm Gateway. The traffic back towards the client
can the be directed to the correct Realm Gateway based on the source address
of the traffic.

Ideally there is a simple router directly behind the Realm Gateways which can
do this source-based routing. Pretty much any modern Unix machine that can
run Linux iptables is usable here. For a simple Ubuntu server for example, the
first thing that is needed is to disable reverse path filtering. Instructions
for it can be found here:

https://nrocco.github.io/2013/04/13/disable-rp-filter.html

The second thing would be to set up iptables rules so that packets from a
certain source are directed to the correct Realm Gateway. Basically, the
system would use a specific outgoing gateway address for a packet based
on its source address (if it comes from the addresses connected to the
protected service). An example config for 2 simultaneous Realm Gateways is
below. Note that the rgw1 and rgw2 tables should have been created for the
system and iptables should have been installed:
```
# iptables -A PREROUTING -s <prot.serv.addr1 for RGW1> -t mangle -j MARK --set-mark 1
# iptables -A PREROUTING -s <prot.serv.addr2 for RGW2> -t mangle -j MARK --set-mark 2
# ip rule add fwmark 1 table rgw1
# ip rule add fwmark 2 table rgw2
# ip route add default via <RGW1 private side addr> dev <iface connected to RGW1> table rgw1
# ip route add default via <RGW2 private side addr> dev <iface connected to RGW2> table rgw2
```

If a nested Realm Gateways are used, the nested Realm Gateway code should be
adjusted so that it can support predetermined access address allocation based
on the front line Realm Gateway address. This then links specific address from
the nested Realm Gateway to a specific front-line Realm Gateway and the source-
based routing can be used. A link to a modified code for the Realm Gateway for
this purpose is added to here in near future.


## Additional Public DNS server software
This repository also contains a simple, "public" DNS relay software that can be
used to emulate some public DNS server in a simplistic manner. This software
has the same dependencies as the custom DNS relay. This program can be used
to forward DNS queries towards the custom DNS relay or towards Realm Gateway
and it can add ECS client subnet information to queries it handles. The
software parameters such as server address can be set by editing the global
variables at the beginning of the code before running the program.
