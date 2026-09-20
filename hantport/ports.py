"""Port specifications, the internal service database, and scan profiles.

IMPORTANT HONESTY RULE
----------------------
SERVICE_DB is only a *known port association* table (like /etc/services).
It is used as a HINT. A service is only reported with HIGH/MEDIUM confidence
when there is real protocol evidence (banner, HTTP response, TLS handshake,
protocol probe). Port-number-only matches are always reported with LOW
confidence and the evidence string "port-number association only".
"""
from __future__ import annotations

from .util import InputError

# ---------------------------------------------------------------------------
# Known port association table (port -> (service name, description)).
# Curated from IANA-style assignments; used as hints only.
# ---------------------------------------------------------------------------
SERVICE_DB = {
    1: ("tcpmux", "TCP Port Service Multiplexer"), 5: ("rje", "Remote Job Entry"),
    7: ("echo", "Echo"), 9: ("discard", "Discard"), 11: ("systat", "System Status"),
    13: ("daytime", "Daytime"), 17: ("qotd", "Quote of the Day"),
    19: ("chargen", "Character Generator"), 20: ("ftp-data", "FTP Data"),
    21: ("ftp", "File Transfer Protocol"), 22: ("ssh", "Secure Shell"),
    23: ("telnet", "Telnet"), 25: ("smtp", "Simple Mail Transfer Protocol"),
    37: ("time", "Time Protocol"), 42: ("nameserver", "Host Name Server"),
    43: ("whois", "WHOIS"), 49: ("tacacs", "TACACS+"), 53: ("domain", "DNS"),
    67: ("bootps", "DHCP Server"), 68: ("bootpc", "DHCP Client"),
    69: ("tftp", "Trivial FTP"), 70: ("gopher", "Gopher"), 79: ("finger", "Finger"),
    80: ("http", "Hypertext Transfer Protocol"), 88: ("kerberos", "Kerberos"),
    102: ("iso-tsap", "ISO-TSAP"), 110: ("pop3", "Post Office Protocol v3"),
    111: ("rpcbind", "RPC Bind / Portmapper"), 113: ("ident", "Ident/Auth service"),
    119: ("nntp", "Network News Transfer"), 123: ("ntp", "Network Time Protocol"),
    135: ("msrpc", "Microsoft RPC"), 137: ("netbios-ns", "NetBIOS Name Service"),
    138: ("netbios-dgm", "NetBIOS Datagram"), 139: ("netbios-ssn", "NetBIOS Session"),
    143: ("imap", "Internet Message Access Protocol"),
    161: ("snmp", "Simple Network Management"),
    162: ("snmptrap", "SNMP Trap"), 177: ("xdmcp", "X Display Manager"),
    179: ("bgp", "Border Gateway Protocol"), 194: ("irc", "Internet Relay Chat"),
    389: ("ldap", "LDAP"), 427: ("svrloc", "Service Location Protocol"),
    443: ("https", "HTTP over TLS"), 444: ("snpp", "Simple Network Paging"),
    445: ("microsoft-ds", "Microsoft SMB"), 465: ("smtps", "SMTP over TLS"),
    500: ("isakmp", "IKE / IPsec key exchange"), 502: ("modbus", "Modbus industrial protocol"),
    512: ("exec", "Remote Process Execution (rsh)"),
    513: ("login", "Remote Login (rlogin)"), 514: ("shell", "Remote Shell (rsh)"),
    515: ("printer", "Line Printer Daemon"), 523: ("ibm-db2", "IBM DB2"),
    548: ("afp", "Apple Filing Protocol"), 554: ("rtsp", "Real Time Streaming Protocol"),
    587: ("submission", "SMTP Message Submission"), 591: ("filemaker", "FileMaker"),
    593: ("http-rpc-epmap", "HTTP RPC Ep Map"), 623: ("asf-rmcp", "IPMI / ASF RMCP"),
    631: ("ipp", "Internet Printing Protocol"), 636: ("ldaps", "LDAP over TLS"),
    646: ("ldp", "Label Distribution Protocol"), 666: ("doom", "Doom game server"),
    674: ("acap", "Application Configuration Access"),
    749: ("kerberos-adm", "Kerberos Administration"), 750: ("kerberos-iv", "Kerberos IV"),
    873: ("rsync", "rsync file transfer"), 901: ("samba-swat", "Samba SWAT"),
    902: ("vmware-auth", "VMware Authentication Daemon"),
    953: ("rndc", "BIND remote name daemon control"),
    989: ("ftps-data", "FTP Data over TLS"), 990: ("ftps", "FTP over TLS"),
    992: ("telnets", "Telnet over TLS"), 993: ("imaps", "IMAP over TLS"),
    994: ("ircs", "IRC over TLS"), 995: ("pop3s", "POP3 over TLS"),
    1025: ("nfs-or-iis", "NFS or IIS"), 1026: ("win-rpc", "Windows RPC"),
    1027: ("iis", "IIS"), 1029: ("ms-lsa", "Microsoft LSA"),
    1080: ("socks", "SOCKS proxy"), 1099: ("rmiregistry", "Java RMI registry"),
    1110: ("nfsd-status", "NFS server status"), 1158: ("dbcontrol-oms", "Oracle Enterprise Manager"),
    1194: ("openvpn", "OpenVPN"), 1214: ("kazaa", "Kazaa P2P"),
    1241: ("nessus", "Nessus vulnerability scanner"), 1270: ("opsmgr", "Microsoft Operations Manager"),
    1311: ("dell-openmanage", "Dell OpenManage"), 1352: ("lotusnotes", "IBM/Lotus Notes"),
    1433: ("ms-sql-s", "Microsoft SQL Server"), 1434: ("ms-sql-m", "Microsoft SQL Monitor"),
    1521: ("oracle", "Oracle database"), 1524: ("ingreslock", "Ingres DB lock"),
    1600: ("issd", "ISSD"), 1720: ("h323q931", "H.323 call signaling"),
    1723: ("pptp", "Point-to-Point Tunneling Protocol"),
    1755: ("ms-streaming", "Microsoft Streaming"), 1801: ("mms", "Microsoft Media Server"),
    1863: ("msnp", "MSN Messenger"), 1900: ("upnp", "UPnP / SSDP"),
    1935: ("rtmp", "Real Time Messaging Protocol"), 1972: ("intersys-cache", "InterSystems Cache"),
    2000: ("cisco-sccp", "Cisco SCCP (Skinny)"), 2049: ("nfs", "Network File System"),
    2105: ("eklogin", "Kerberos encrypted rlogin"), 2121: ("ftp-agent", "FTP proxy/agent"),
    2161: ("apc-agent", "APC UPS management"), 2179: ("vmrdp", "Hyper-V VM RDP"),
    2222: ("directv-web", "DirecTV web / often alt-SSH"), 2301: ("cpq-wbem", "HP/Compaq WBEM"),
    2381: ("compaq-https", "HP/Compaq HTTPS"), 2401: ("cvspserver", "CVS pserver"),
    2432: ("codasrv", "Coda file system"), 2627: ("webster", "Webster dictionary"),
    2638: ("sybase", "Sybase / SQL Anywhere"), 2809: ("corbaloc", "CORBA LOC"),
    2947: ("gpsd", "GPS daemon"), 2967: ("symantec-av", "Symantec AntiVirus"),
    3000: ("ppp", "User-level PPP / common alt-HTTP"), 3050: ("gds-db", "Firebird/InterBase"),
    3074: ("xbox", "Xbox Live"), 3127: ("squid-http", "Squid HTTP proxy"),
    3128: ("squid", "Squid proxy"), 3130: ("icp", "Internet Cache Protocol"),
    3260: ("iscsi", "iSCSI"), 3268: ("globalcatLDAP", "Active Directory global catalog"),
    3269: ("globalcatLDAPssl", "AD global catalog over TLS"),
    3300: ("decmcc", "DEC MCC"), 3306: ("mysql", "MySQL database"),
    3333: ("dec-notes", "DEC Notes"), 3351: ("btrieve", "Btrieve database"),
    3372: ("msdtc", "Microsoft Distributed Transaction Coordinator"),
    3389: ("ms-wbt-server", "RDP / Terminal Services"), 3390: ("dsc", "Distributed Service Coordinator"),
    3478: ("stun", "STUN NAT traversal"), 3483: ("nss", "Network Status Server"),
    3689: ("daap", "Digital Audio Access (iTunes)"), 3690: ("svn", "Subversion"),
    3776: ("cctv3", "CCTV3"), 3872: ("oem-agent", "OEM agent"),
    4000: ("terabase", "Terabase / alt service"), 4045: ("npp", "NPP"),
    4105: ("shofar", "Shofar"), 4111: ("xgrid", "Apple Xgrid"),
    4172: ("pcoip", "PC-over-IP"), 4190: ("sieve", "ManageSieve mail filtering"),
    4321: ("rwhois", "RWhois"), 4369: ("epmd", "Erlang Port Mapper"),
    4443: ("pharos", "Pharos / alt HTTPS"), 4444: ("nv-video", "NV video / metasploit default"),
    4488: ("confluent-shared", "Confluent shared"), 4500: ("ipsec-nat-t", "IPsec NAT-Traversal"),
    4559: ("hyla-fax", "HylaFAX"), 4569: ("iax", "Inter-Asterisk eXchange"),
    4848: ("appserv-http", "Application Server HTTP"), 4899: ("radmin", "Radmin remote control"),
    4949: ("munin", "Munin monitoring"), 5000: ("upnp", "UPnP / alt HTTP"),
    5001: ("commplex-link", "Commplex Link"), 5003: ("filemaker", "FileMaker"),
    5004: ("avt-profile-1", "RTP audio"), 5005: ("avt-profile-2", "RTP video"),
    5031: ("dmp", "Direct Message Protocol"), 5050: ("mmcc", "Yahoo Messenger"),
    5060: ("sip", "Session Initiation Protocol"), 5061: ("sip-tls", "SIP over TLS"),
    5101: ("admeng", "AD engineering"), 5133: ("nbt-pc", "NetBIOS PC"),
    5150: ("atmp", "Ascend Tunnel Management"), 5190: ("aol", "AIM / ICQ"),
    5222: ("xmpp-client", "XMPP client"), 5223: ("xmpp-client-ssl", "XMPP client (legacy SSL)"),
    5269: ("xmpp-server", "XMPP server-to-server"), 5280: ("xmpp-bosh", "XMPP BOSH"),
    5298: ("presence", "Presence information"), 5351: ("nat-pmp", "NAT Port Mapping Protocol"),
    5353: ("mdns", "Multicast DNS"), 5355: ("llmnr", "Link-Local Multicast Name Resolution"),
    5400: ("pcduo", "PCDuo remote control"), 5432: ("postgresql", "PostgreSQL database"),
    5440: ("ohmiremote", "Ohmi remote"), 5454: ("apc", "APC power protection"),
    5550: ("fcp", "Fibre Channel over IP? / FCP"), 5554: ("sgi-esphttp", "SGI ESP HTTP"),
    5555: ("personal-agent", "Personal Agent / alt control"),
    5631: ("pcanywheredata", "pcAnywhere data"), 5632: ("pcanywherestat", "pcAnywhere status"),
    5666: ("nrpe", "Nagios NRPE"), 5671: ("amqps", "AMQP over TLS"),
    5672: ("amqp", "AMQP messaging"), 5683: ("coap", "Constrained Application Protocol"),
    5800: ("vnc-http", "VNC web interface"), 5900: ("vnc", "Virtual Network Computing"),
    5901: ("vnc-1", "VNC display :1"), 6000: ("x11", "X Window System"),
    6001: ("x11-1", "X Window System :1"), 6002: ("x11-2", "X Window System :2"),
    6101: ("backup-exec", "Veritas Backup Exec"), 6112: ("dtspcd", "DTSPCD"),
    6346: ("gnutella-svc", "Gnutella P2P"), 6347: ("gnutella-rtr", "Gnutella router"),
    6379: ("redis", "Redis in-memory store"), 6500: ("boks", "BOKS security"),
    6543: ("mythtv", "MythTV backend"), 6566: ("sane-port", "SANE network scanning"),
    6600: ("ms-smlbiz", "MS Small Business"), 6665: ("ircu", "IRC"),
    6666: ("ircu", "IRC"), 6667: ("ircu", "IRC"), 6668: ("ircu", "IRC"),
    6669: ("ircu", "IRC"), 6697: ("ircs-u", "IRC over TLS"),
    6699: ("napster", "Napster"), 6789: ("ibm-db2", "IBM DB2"),
    6839: ("amandaidx", "Amanda index"), 6881: ("bittorrent-tracker", "BitTorrent"),
    6969: ("acmsoda", "ACMSoda"), 7000: ("afs3-fileserver", "AFS file server"),
    7001: ("afs3-callback", "AFS callback"), 7002: ("afs3-prserver", "AFS protection"),
    7003: ("afs3-vlserver", "AFS volume location"), 7004: ("afs3-kaserver", "AFS Kerberos"),
    7005: ("afs3-volser", "AFS volume server"), 7009: ("afs3-rmtsys", "AFS remote cache"),
    7070: ("realserver", "RealServer / alt HTTP"), 7100: ("font-service", "X font server"),
    7443: ("oracleas-https", "Oracle Application Server HTTPS"),
    7547: ("cwmp", "TR-069 CPE WAN Management (routers)"),
    7626: ("soap-http", "SOAP over HTTP"), 7676: ("imqbrokerd", "IMQ broker"),
    7777: ("cbt", "CBT / alt services"), 7778: ("interwise", "InterWise"),
    8000: ("http-alt", "HTTP alternate / iRDMI"), 8001: ("vcom-tunnel", "VCOM tunnel"),
    8008: ("http-alt", "HTTP alternate (RFC 8615)"), 8009: ("ajp13", "Apache JServ Protocol"),
    8010: ("xmpp", "XMPP"), 8080: ("http-proxy", "HTTP proxy / alternate"),
    8081: ("sunproxyadmin", "Sun proxy admin"), 8086: ("d-s-n", "Distributed SCADA"),
    8087: ("simplifymedia", "Simplify Media"), 8088: ("radan-http", "Radan HTTP"),
    8090: ("opsmessaging", "Ops messaging"), 8100: ("xprint-server", "X print server"),
    8118: ("privoxy", "Privoxy proxy"), 8123: ("http-alt", "Home Assistant / alt HTTP"),
    8140: ("puppet", "Puppet agent"), 8181: ("intermapper", "Intermapper network monitor"),
    8194: ("blp1", "Bloomberg data"), 8200: ("trivnet1", "Trivnet"),
    8222: ("gprecorder", "GP recorder"), 8230: ("crowd", "Atlassian Crowd"),
    8243: ("synapse-nhttps", "Synapse NHTTPS"), 8280: ("synapse-nhttp", "Synapse NHTTP"),
    8291: ("winbox", "MikroTik Winbox"), 8333: ("bitcoin", "Bitcoin mainnet"),
    8400: ("cvd", "Collabra video"), 8443: ("https-alt", "HTTPS alternate"),
    8554: ("rtsp-alt", "RTSP alternate"), 8600: ("asterix", "Asterix surveillance data"),
    8765: ("ultraseek-http", "Ultraseek HTTP"), 8883: ("mqtts", "MQTT over TLS"),
    8888: ("sun-answerbook", "HTTP alternate"), 8989: ("sunwebadmins", "Sun web admin"),
    8990: ("http-wmap", "HTTP web mapping"), 9000: ("cslistener", "CSListener / alt HTTP"),
    9001: ("etlservicemgr", "ETL service manager"), 9010: ("sdr", "Secure Data Replicator"),
    9042: ("cassandra", "Apache Cassandra"), 9043: ("ibm-mqtt", "IBM MQTT"),
    9060: ("CardWeb-IO", "CardWeb IO"), 9080: ("websphere-http", "IBM WebSphere HTTP"),
    9090: ("websm", "Web-based system manager / alt HTTP"),
    9091: ("xmltec-xmlmail", "XMLTech XMLMail"), 9092: ("XmlIpcRegSvc", "XML IPC"),
    9100: ("jetdirect", "Printer (HP JetDirect)"), 9111: ("DragonIDSConsole", "Dragon IDS"),
    9200: ("elasticsearch-http", "Elasticsearch HTTP"), 9300: ("vrace", "VRace"),
    9418: ("git", "Git version control"), 9443: ("wsman", "WS-Management / alt HTTPS"),
    9500: ("ismserver", "ISMServer"), 9535: ("mngsuite", "Management Suite"),
    9595: ("mercury-disc", "Mercury Discovery"), 9618: ("condor", "HTCondor"),
    9666: ("zoomcp", "Zoom Control Panel"), 9800: ("davsrc", "WebDAV source"),
    9875: ("sapv1", "SAP"), 9898: ("monkeycom", "MonkeyCom"),
    9900: ("d20nm", "Data20"), 9981: ("dasg", "DASG"),
    9999: ("distinct", "Distinct / alt services"), 10000: ("ndmp", "NDMP backup / webmin"),
    10050: ("zabbix-agent", "Zabbix agent"), 10051: ("zabbix-trapper", "Zabbix trapper"),
    10200: ("trisoap", "Tripwire SOAP"), 10443: ("cirrossp", "Cirros SP"),
    11211: ("memcached", "Memcached"), 11371: ("hkp", "OpenPGP HTTP keyserver"),
    11720: ("h323callsigalt", "H.323 alternate"), 12000: ("cce4x", "CCE4X"),
    12345: ("italk", "Italk chat"), 13720: ("bprd", "NetBackup request daemon"),
    13721: ("bpdbm", "NetBackup database"), 13724: ("vnetd", "NetBackup vnetd"),
    13782: ("bpcd", "NetBackup client daemon"), 14000: ("scotty-ft", "SCOTTY file transfer"),
    14141: ("vcs-app", "Veritas Cluster Server"), 14154: ("cadview-3d", "CADView 3D"),
    15000: ("hydap", "Hypack data"), 15200: ("ndmps", "NDMP over TLS"),
    16010: ("hbase-master", "HBase Master web UI"), 16030: ("hbase-regionserver", "HBase RegionServer"),
    16992: ("amt-soap-http", "Intel AMT"), 16993: ("amt-soap-https", "Intel AMT over TLS"),
    17007: ("isode-dua", "ISODE DUA"), 17235: ("ssh-mgmt", "SSH management"),
    17500: ("db-lsp", "Dropbox LAN sync"), 17777: ("sw-orion", "SolarWinds Orion"),
    18000: ("biimenu", "Beckman Instruments"), 18181: ("opsec-cvp", "Check Point OPSEC CVP"),
    18241: ("checkpoint-rtm", "Check Point RTM"), 18463: ("ac-cluster", "AC cluster"),
    19000: ("igrid", "iGrid"), 19216: ("keyserver", "Key server"),
    19398: ("mtrgtrans", "MTRG transactions"), 19410: ("hp-sco", "HP SCO"),
    19788: ("mle", "Mesh Link Establishment"), 19999: ("dnp-sec", "DNP Secure"),
    20000: ("dnp", "Distributed Network Protocol 3"), 20005: ("openwebnet", "OpenWebNet"),
    20034: ("nburn", "NetBurner"), 20200: ("transact", "TransAct"),
    20480: ("emweblogin", "EMWebLogin"), 20670: ("track", "Track"),
    21000: ("irtrans", "IRTrans control"), 21554: ("dfserver", "DF server"),
    21845: ("webphone", "Webphone"), 22000: ("snapenetio", "SnapENET"),
    23000: ("inovaport1", "Inova port 1"), 23001: ("inovaport2", "Inova port 2"),
    24000: ("med-ltp", "Med LTP"), 24242: ("filesphere", "FileSphere"),
    24344: ("intel-rci", "Intel RCI"), 24677: ("af", "Accounting & Finance"),
    26000: ("quake", "Quake game server"), 26260: ("ezproxy", "EzProxy"),
    27017: ("mongodb", "MongoDB database"), 27374: ("subseven", "SubSeven trojan (historic)"),
    28080: ("thor-engine", "Thor engine"), 28102: ("loomstream?", "Bloomberg"),
    28369: ("couchdb", "CouchDB"), 30000: ("ndmps?", "NDMP secure"),
    30400: ("nucleus-sand", "Nucleus SAND"), 30999: ("ovobs", "OpenView OBS"),
    31337: ("elite", "Back Orifice (historic)"), 31457: ("tetrinet", "TetriNET"),
    32034: ("iracinghelper", "iRacing helper"), 32768: ("filenet-tms", "FileNet TMS"),
    32769: ("filenet-rpc", "FileNet RPC"), 32770: ("filenet-nch", "FileNet NCH"),
    32771: ("filenet-rmi", "FileNet RMI"), 33434: ("traceroute", "Traceroute probes"),
    34268: ("rss-acct", "RSS accounting"), 34567: ("dhanalakshmi", "dhanalakshmi"),
    34962: ("proficon-port", "Profibus config"), 35000: ("rtmp-port", "RTMP"),
    36001: ("allpeers", "AllPeers"), 36865: ("kastenxpipe", "KastenX pipe"),
    37475: ("neckar", "science+computing Venus"), 38201: ("galaxy7-telephony", "Galaxy7 telephony"),
    38865: ("vrdp", "VirtualBox VRDP"), 40000: ("safetynetp", "SafetyNET p"),
    40404: ("sptx", "SPTX"), 41111: ("xgrid-alt", "Xgrid alternate"),
    41230: ("napster", "Napster"), 41717: ("ganymede", "Ganymede"),
    42508: ("candp", "Computer Associates"), 42510: ("caerpc", "CA eTrust"),
    43188: ("reachout", "ReachOut remote control"), 43189: ("ndm-agent-port", "NDM agent"),
    44321: ("pmcd", "PCP collector"), 44322: ("pmcdproxy", "PCP proxy"),
    44442: ("coldfusion-auth", "ColdFusion auth"), 44443: ("coldfusion-auth", "ColdFusion auth"),
    44818: ("ethernet-ip", "EtherNet/IP industrial"), 47808: ("bacnet", "BACnet building automation"),
    48000: ("nimcontroller", "NIM controller"), 49152: ("sunrpc-port", "Sun RPC dynamic"),
    49400: ("compaqdiag", "Compaq diagnostics"), 50000: ("ibm-db2", "IBM DB2"),
    50001: ("db2", "DB2"), 50002: ("rfe", "Radio Free Ethernet"),
    50300: ("sgi-dgl", "SGI DGL"), 50500: ("cncp", "CNCP"),
    51103: ("restore", "Restore"), 52673: ("stickies", "Stickies notes"),
    52822: ("mnet-discovery", "mnet discovery"), 53571: ("max", "MAX"),
    54321: ("bo2k", "Back Orifice 2000 (historic)"), 55555: ("dbisam", "DBISAM"),
    55600: ("isqlplus", "iSQL*Plus"), 56364: ("track", "Track"),
    57797: ("vdm", "VDM"), 58080: ("vnc-http", "VNC web"),
    60020: ("vlsi-lm", "VLSI license manager"), 60443: ("dmt", "DMT"),
    61532: ("stat-1", "stat 1"), 62078: ("iphone-sync", "iPhone sync"),
    63419: ("jmact5", "JMail"), 64179: ("pstdupload", "PST upload"),
    64435: ("reversion", "Reversion"), 64738: ("murmur", "Mumble VoIP"),
    64817: ("netxms-agent", "NetXMS agent"), 65129: ("mcer-port", "MCER"),
    65535: ("unknown", "Reserved/unknown"),
}

# Frequency-ranked most-common open ports (nmap-style top list).
TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81,
    6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
    49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153,
    8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357,
    427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028,
    873, 1755, 2717, 4899, 9100, 119, 37,
]

# Scan profiles: name -> (documentation, expand())
PROFILES = {
    "fast": ("Top 100 most common TCP ports (frequency-ranked)", lambda: list(TOP_PORTS)),
    "common": ("Ports 1-1024 plus the top 100 most common ports",
               lambda: sorted(set(range(1, 1025)) | set(TOP_PORTS))),
    "thorough": ("All TCP ports 1-10000", lambda: list(range(1, 10001))),
    "full": ("All 65535 TCP ports", lambda: list(range(1, 65536))),
}


def port_hint(port: int):
    """Return the (name, description) known association for a port, or None."""
    return SERVICE_DB.get(port)


def profile_names():
    return sorted(PROFILES)


def profile_docs():
    return {name: desc for name, (desc, _) in PROFILES.items()}


def profile_ports(name: str):
    if name not in PROFILES:
        raise InputError(
            f"Unknown profile '{name}'. Available profiles: {', '.join(profile_names())}. "
            "Use 'hant profiles' to see what each profile scans."
        )
    return PROFILES[name][1]()


def top_ports(n: int):
    """Return the N most scan-worthy ports.

    1-100: frequency-ranked TOP_PORTS. Beyond that: the rest of the curated
    service database in ascending order. If n exceeds the curated data, the
    remaining ports are appended in plain ascending order (documented
    behaviour - no fake frequency claims) so the result is always exactly n.
    """
    if isinstance(n, bool) or not isinstance(n, int):
        raise InputError(f"--top-ports must be an integer, got {n!r}.")
    if n < 1 or n > 65535:
        raise InputError(f"--top-ports must be between 1 and 65535 (got {n}).")
    if n <= len(TOP_PORTS):
        return list(TOP_PORTS[:n])
    result = list(TOP_PORTS)
    in_top = set(TOP_PORTS)
    extras = sorted(p for p in SERVICE_DB if p not in in_top)
    result.extend(extras[: n - len(result)])
    if len(result) < n:  # documented fallback: ascending order, no fake ranking
        have = set(result)
        result.extend(p for p in range(1, 65536) if p not in have)
        result = result[:n]
    return result


def parse_port_spec(spec: str):
    """Parse '80', '1-1024', '22,80,443' or mixes like '1-100,443,9000-9002'.

    Returns a sorted list of unique ports. Raises InputError on any
    malformed element, out-of-range value, inverted range, or duplicates.
    """
    if spec is None or not str(spec).strip():
        raise InputError("Empty port specification.")
    parsed = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            raise InputError(f"Invalid port specification '{spec}': empty element.")
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2 or not bounds[0].strip().isdigit() or not bounds[1].strip().isdigit():
                raise InputError(f"Invalid port range '{part}' in '{spec}': expected START-END.")
            lo, hi = int(bounds[0]), int(bounds[1])
            if lo < 1 or hi > 65535 or lo > hi:
                raise InputError(
                    f"Invalid port range '{part}': must satisfy 1 <= start <= end <= 65535."
                )
            parsed.extend(range(lo, hi + 1))
        else:
            if not part.isdigit():
                raise InputError(f"Invalid port '{part}' in '{spec}': not a number.")
            p = int(part)
            if not 1 <= p <= 65535:
                raise InputError(f"Invalid port {p} in '{spec}': must be between 1 and 65535.")
            parsed.append(p)
    seen = set()
    dupes = sorted({p for p in parsed if p in seen or seen.add(p)})
    if dupes:
        shown = ", ".join(str(d) for d in dupes[:5])
        raise InputError(f"Duplicate ports in specification '{spec}': {shown}.")
    return sorted(set(parsed))
