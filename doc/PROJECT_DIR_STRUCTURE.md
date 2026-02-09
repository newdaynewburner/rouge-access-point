# Project Directory Structure
All project-related components are stored in a single parent git repository, with each of the core components of the program stored in their own child git repositories that are located in the `core/` directory. Below is a diagram of how it appears in the filesystem tree and an explaination of what each core component does:

*Directory Tree*
```
core/
core/ap-host/
core/data-pipelines/
core/data-storage/
core/dhcp-server/
core/dns-server/
core/http-server/
```

*Core Components*
These components are the ones integral to hosting the AP and to facilitating attacks, and each one exists in its own repository since each one is self-sufficient and capable of running independently of the others or of the rest of the project, and are designed to be more of an intermediary layer used to interact with the underlying sub-system dealt with by the component than they are collections of use-case specific functionality; basically, it exists so other things can do things with the aspect of the rouge AP that it controls, not to do those things themselves. 

1. **ap-host** - Handles the broadcasting of the AP and device authentication, which are facilitated with an instance of hostapd under the hood, and provides a centralized interface for preforming various functions related to controlling the hostapd instance or to the actual AP broadcast itself
2. **dhcp-server** - Acts as the gateway's DHCP server, facilitating IPv4 and IPv6 address assignment, and acting as the entry point for per-client data collection.
3. **dns-server** - A multi-purpose DNS server that acts as the authoritative nameserver for the local domain, also providing general DNS query responses as the network's default DNS server (as specified to the client during DHCP IP address assignment). All DNS-related attacks are also facilitated through this server.
4. **http-server** - Facilitates the serving of webpages/web content and domain/SSL configuration on an as-needed basis through Apache vHosts, provides captive portal functionality, as well as the necessary REST API's necessary for things like the captive portal to make changes to the gateway, such as removing a client device from enforced captivity. 

The remaining two core components exist to collect, normalize, and store data produced by the previous components in a sane, comprehensive manner so these datasets can be used by other things to glean insights and analyze patterns.

5. **data-pipelines** - This contains everything surrounding the process of obtaining the raw data from the other components, extracting the relevant datapoints, and sending them onwards to be stored in the appropriate place. High level data collection flow:
`[NEW DATA APPEARS ELSEWHERE] -> [FED INTO/PULLED INTO PIPELINE AS RAW DATA] -> [DATAPOINTS IDENTIFIED AND EXTRACTED] -> [DATAPOINTS NORMALIZED AND GROUPED] -> [PROCESSED DATA FED INTO DATA STORAGE COMPONENT]`
6. **data-storage** - Once the data has been processed into normalized datapoints/datasets it is passed to this component, which stores the new data in the appropriate place based on its source and type, determines if the data arriving for intake should trigger any particular action preformed when the data meets certain criteria (alerting when a new device joins, hit on phishing page, etc.), and preforming generalized analysis of the complete dataset to get certain relevant statistics. 

All of these components are pieced together into a well meshed web of gears by the main project file `rouge-access-point.py` and the modules in `lib/`
 
