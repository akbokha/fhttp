# fHTTP <img src="/media/fhttp_logo.ico" width="50" align="left"/>
*fHTTP* is a fully-fledged ARP spoofing tool. The spoofing capabilities can be combined with other attacks which target both the confidentiality and integrity of the users and/or systems on the same (local) network by providing our users with the abilities to filter- and inject malicious code into traffic which is retrieved, manipulated and eventually forwarded. In particular, we provide our users with the following options:

* *Network reconnaissance*: retrieving an `IP`-to-`MAC` mapping for all the devices on the (local) network to be able to identify victims/targets and forward packets appropriately.
* Acquiring *MitM position*: Persistent `ARP` cache poisoning
* *Sniffing/filtering of packets:*
    * retrieval of insecure cookies &rarr; can be exploited for session-hijacking
    * retrieval of `HTTP` request headers
    * filtering `TCP` packets based on a self-specified regular-expression
* *Modifying (`TCP`) packets:*
    * modification of the `Accept-Encoding` header  &rarr; can change it to `identity` to remove any encoding (e.g. compression algorithm)
    * injection of malicious code into an `img`-tag
    * removal of the `Content-Security-Policy (CSP)`  header &rarr; to prevent mitigation of XSS and injection attacks

#### Project objectives
The main objective is to build an *easy-to-use* interface.
- The users should be able to perform the aforementioned attacks without the need of a substantial understanding of the underlying vulnerabilities &rightarrow; users should only be bothered with input/selection/configurations
- The users should be able to perform the aforementioned attack without the need for (frequent) usage of a command-line interface &rightarrow; A GUI is built using *TkInter*

#### Dependencies
- For VMs/systems with multiple network interfaces: our application is only able to operate on the primary network interface.
- Python version 2.7
- Scapy version 2.3.1
- TkInter version 8.5

#### Usage
Once the source code has been downloaded one can start the application by simply running the following command: `python fhttp.py`  Once you close the welcoming pop-up one should be faced with the following interface:

<img src="/media/fhttp.png"/>

There is a status frame indicated by `[status]` which will display information about which underlying processes are running and using what configuration (e.g. ARP spoofing `X` and `Y`, Scanning the local network etc.). The output/input frame is the larger of the two (and scrollable). It show the output (`[output + timestamp]`) (i.e. filtered packets/content) and shows/gives a backlog of the user-input (`[input + timestamp]`).

The rest of the attack-engineering process should then be rather trivial due to the straightforward steps and configuration possibilities.

<img src="/media/network_scan.png"/>
Scanning the local network and selecting the victim(s) and target.

<img src="/media/arp_spoofing.png"/>
Selection is passed on to this frame where the user can double-check/change the configuration and eventually start the `ARP` spoofing thread.

<img src="/media/cookie_filtering.png"/>
The user can dynamically (run-time) add/remove packet-filters and (de-)activate packet-modifyers and -injectors.
