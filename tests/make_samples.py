"""Generate the test fixtures in samples/.

These are committed, but keep the generator so they can be rebuilt. Script
output lives in an XML attribute, where a literal newline is normalised to a
space by any conforming parser; nmap writes &#10; instead, so the fixtures have
to as well — which is why they are generated rather than hand-written.

Run:  python tests/make_samples.py
"""

import os
import textwrap

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")


def attr(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\t", "&#9;")
        .replace("\n", "&#10;")
    )


def script(script_id: str, body: str, indent: str = "        ") -> str:
    text = "\n" + textwrap.dedent(body).strip("\n") + "\n"
    return f'{indent}<script id="{script_id}" output="{attr(text)}"/>'


# ---------------------------------------------------------------------------
# sample.xml
# ---------------------------------------------------------------------------

VULNERS = """
  cpe:/a:apache:http_server:2.4.49:
    CVE-2021-42013  9.8  https://vulners.com/cve/CVE-2021-42013
    CVE-2021-41773  7.5  https://vulners.com/cve/CVE-2021-41773
"""

HTTP_TITLE = """
  Apache/2.4.49 (Unix) Server at web01.lab.local Port 80
"""

SAMPLE_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -p 22,25,80,3306,8080 -oX sample.xml 10.10.10.5 10.10.10.6" start="1704067200" startstr="Mon Jan  1 00:00:00 2024" version="7.94" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="5" services="22,25,80,3306,8080"/>
  <verbose level="0"/>
  <debugging level="0"/>
  <host starttime="1704067200" endtime="1704067210">
    <status state="up" reason="echo-reply" reason_ttl="63"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="web01.lab.local" type="PTR"/>
    </hostnames>
    <ports>
      <extraports state="closed" count="0">
        <extrareasons reason="resets" count="0"/>
      </extraports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="63"/>
        <service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:7.4</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="25">
        <state state="open" reason="syn-ack" reason_ttl="63"/>
        <service name="smtp" product="Postfix smtpd" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="63"/>
        <service name="http" product="Apache httpd" version="2.4.49" extrainfo="(Unix)" method="probed" conf="10">
          <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
        </service>
{script("vulners", VULNERS)}
{script("http-server-header", HTTP_TITLE)}
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack" reason_ttl="63"/>
        <service name="mysql" product="MySQL" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack" reason_ttl="63"/>
        <service name="tcpwrapped" method="probed" conf="8"/>
      </port>
    </ports>
    <times srtt="1000" rttvar="500" to="100000"/>
  </host>
  <host starttime="1704067210" endtime="1704067260">
    <status state="up" reason="user-set" reason_ttl="0"/>
    <address addr="10.10.10.6" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <extraports state="filtered" count="65535">
        <extrareasons reason="no-responses" count="65535"/>
      </extraports>
    </ports>
    <times srtt="2000" rttvar="900" to="100000"/>
  </host>
  <runstats>
    <finished time="1704067260" timestr="Mon Jan  1 00:01:00 2024" summary="Nmap done" elapsed="60.00" exit="success"/>
    <hosts up="2" down="0" total="2"/>
  </runstats>
</nmaprun>
"""

# ---------------------------------------------------------------------------
# sample.gnmap
# ---------------------------------------------------------------------------

SAMPLE_GNMAP = """\
# Nmap 7.94 scan initiated Mon Jan  1 01:00:00 2024 as: nmap -sV -T5 -oG sample.gnmap 10.10.10.5 10.10.10.6
Host: 10.10.10.5 (web01.lab.local)\tStatus: Up
Host: 10.10.10.5 (web01.lab.local)\tPorts: 22/open/tcp//ssh//OpenSSH 7.4 (protocol 2.0)/, 80/open/tcp//http//Apache httpd 2.4.49/, 443/filtered/tcp//https///\tIgnored State: closed (997)
Host: 10.10.10.6 ()\tStatus: Up
Host: 10.10.10.6 ()\tPorts: 22/open/tcp//ssh///\tIgnored State: filtered (999)
# Nmap done at Mon Jan  1 01:00:30 2024 -- 2 IP addresses (2 hosts up) scanned in 30.00 seconds
"""

# ---------------------------------------------------------------------------
# sample.nmap  (healthy certificate: regression guard for "Not valid after")
# ---------------------------------------------------------------------------

SAMPLE_NMAP = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-01 02:00 UTC
Nmap scan report for db01.lab.local (10.10.10.11)
Host is up (0.00089s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
5432/tcp open  postgresql PostgreSQL DB 11.7
| ssl-cert: Subject: commonName=db01.lab.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-06-01T00:00:00
|_Not valid after:  2033-06-01T00:00:00

Nmap scan report for 10.10.10.12
Host is up (0.0012s latency).
Not shown: 1000 filtered tcp ports (no-response)

Nmap done: 2 IP addresses (2 hosts up) scanned in 4.21 seconds
"""

# ---------------------------------------------------------------------------
# sample-scripts.xml  (a genuinely broken host, mixed healthy/weak values)
# ---------------------------------------------------------------------------

FTP_ANON = """
  Anonymous FTP login allowed (FTP code 230)
  drwxrwxrwx    2 0        0            4096 Jan 01 00:00 incoming
  -rw-r--r--    1 0        0             219 Jan 01 00:00 readme.txt
"""

SSH2_ALGOS = """
  kex_algorithms: (4)
      curve25519-sha256@libssh.org
      diffie-hellman-group-exchange-sha256
      diffie-hellman-group1-sha1
      ecdh-sha2-nistp256
  server_host_key_algorithms: (2)
      ssh-rsa
      ssh-dss
  encryption_algorithms: (4)
      aes128-ctr
      aes256-ctr
      aes128-cbc
      arcfour256
  mac_algorithms: (4)
      hmac-sha2-256
      umac-64-etm@openssh.com
      hmac-md5
      hmac-sha1-96
  compression_algorithms: (2)
      none
      zlib@openssh.com
"""

SSH_HOSTKEY = """
  1024 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 (RSA)
  1024 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00 (DSA)
  256 ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89 (ED25519)
"""

DNS_RECURSION = """
  Recursion appears to be enabled
"""

HTTP_METHODS = """
  Supported Methods: GET HEAD POST OPTIONS PUT DELETE TRACE
  Potentially risky methods: PUT DELETE TRACE
"""

SSL_DH_PARAMS = """
  VULNERABLE:
  Diffie-Hellman Key Exchange Insufficient Group Strength
    State: VULNERABLE
      Transport Layer Security (TLS) services that use Diffie-Hellman groups of
      insufficient strength, especially those using one of a few commonly shared
      groups, may be susceptible to passive eavesdropping attacks.
      Check results:
        WEAK DH GROUP 1
              Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA
              Modulus Type: Safe prime
              Modulus Source: Unknown/Custom-generated
              Modulus Length: 1024
              Generator Length: 8
              Public Key Length: 1024
    References:
      https://weakdh.org
"""

SSL_CIPHERS = """
  SSLv3:
    ciphers:
      TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C
      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
    compressors:
      NULL
    cipher preference: server
  TLSv1.0:
    ciphers:
      TLS_RSA_EXPORT_WITH_RC4_40_MD5 (rsa 2048) - E
      TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 1024) - C
    compressors:
      NULL
    cipher preference: server
  TLSv1.2:
    ciphers:
      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
    compressors:
      NULL
    cipher preference: server
  least strength: E
"""

SSL_CERT_BAD = """
  Subject: commonName=old.lab.local/organizationName=Lab/countryName=GB
  Issuer: commonName=old.lab.local/organizationName=Lab/countryName=GB
  Public Key type: rsa
  Public Key bits: 1024
  Signature Algorithm: sha1WithRSAEncryption
  Not valid before: 2014-01-01T00:00:00
  Not valid after:  2016-01-01T00:00:00
  MD5:   1111 2222 3333 4444 5555 6666 7777 8888
  SHA-1: aaaa bbbb cccc dddd eeee ffff 0000 1111 2222 3333
"""

HEARTBLEED = """
  VULNERABLE:
  The Heartbleed Bug is a serious vulnerability in the popular OpenSSL
  cryptographic software library. It allows for stealing information intended
  to be protected by SSL/TLS encryption.
    State: VULNERABLE
    Risk factor: High
    References:
      https://www.openssl.org/news/secadv_20140407.txt
"""

MYSQL_EMPTY = """
  root account has empty password
"""

REDIS_INFO = """
  Version: 5.0.7
  redis_version: 5.0.7
  redis_mode: standalone
  os: Linux 5.4.0-generic x86_64
  tcp_port: 6379
"""

SMB_SECURITY_MODE = """
  account_used: guest
  authentication_level: user
  challenge_response: supported
  message_signing: disabled (dangerous, but default)
"""

SMB_PROTOCOLS = """
  dialects:
    NT LM 0.12 (SMBv1) [dangerous, but default]
    2.0.2
    2.1
"""

SAMPLE_SCRIPTS_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC --script vuln,ssl-enum-ciphers,ssl-dh-params,ssh2-enum-algos,smb-security-mode,smb-protocols -p- -oX sample-scripts.xml 10.10.10.20" start="1704067200" startstr="Mon Jan  1 00:00:00 2024" version="7.94" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="65535" services="1-65535"/>
  <host starttime="1704067200" endtime="1704067400">
    <status state="up" reason="echo-reply" reason_ttl="64"/>
    <address addr="10.10.10.20" addrtype="ipv4"/>
    <hostnames>
      <hostname name="legacy.lab.local" type="PTR"/>
    </hostnames>
    <ports>
      <extraports state="closed" count="65525">
        <extrareasons reason="resets" count="65525"/>
      </extraports>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ftp" product="vsftpd" version="2.3.4" method="probed" conf="10">
          <cpe>cpe:/a:beasts:vsftpd:2.3.4</cpe>
        </service>
{script("ftp-anon", FTP_ANON)}
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="5.3" extrainfo="protocol 2.0" method="probed" conf="10"/>
{script("ssh2-enum-algos", SSH2_ALGOS)}
{script("ssh-hostkey", SSH_HOSTKEY)}
      </port>
      <port protocol="tcp" portid="23">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="telnet" product="Linux telnetd" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="53">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="domain" product="ISC BIND" version="9.8.2" method="probed" conf="10"/>
{script("dns-recursion", DNS_RECURSION)}
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="Apache httpd" version="2.2.15" method="probed" conf="10"/>
{script("http-methods", HTTP_METHODS)}
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="https" product="Apache httpd" version="2.2.15" tunnel="ssl" method="probed" conf="10"/>
{script("ssl-dh-params", SSL_DH_PARAMS)}
{script("ssl-enum-ciphers", SSL_CIPHERS)}
{script("ssl-cert", SSL_CERT_BAD)}
{script("ssl-heartbleed", HEARTBLEED)}
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="mysql" product="MySQL" version="5.5.40" method="probed" conf="10"/>
{script("mysql-empty-password", MYSQL_EMPTY)}
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="redis" product="Redis key-value store" version="5.0.7" method="probed" conf="10"/>
{script("redis-info", REDIS_INFO)}
      </port>
    </ports>
    <hostscript>
{script("smb-security-mode", SMB_SECURITY_MODE, indent="      ")}
{script("smb-protocols", SMB_PROTOCOLS, indent="      ")}
    </hostscript>
    <times srtt="1000" rttvar="500" to="100000"/>
  </host>
  <runstats>
    <finished time="1704067400" timestr="Mon Jan  1 00:03:20 2024" summary="Nmap done" elapsed="200.00" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""

# ---------------------------------------------------------------------------
# sample-healthy.xml  (well-configured host; any defect reported is a regression)
# ---------------------------------------------------------------------------

H_SSL_CIPHERS = """
  TLSv1.2:
    ciphers:
      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (secp256r1) - A
    compressors:
      NULL
    cipher preference: server
  TLSv1.3:
    ciphers:
      TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
      TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
    cipher preference: server
  least strength: A
"""

H_SSL_CERT = """
  Subject: commonName=www.example.com
  Subject Alternative Name: DNS:www.example.com, DNS:example.com
  Issuer: commonName=R3/organizationName=Let's Encrypt/countryName=US
  Public Key type: ec
  Public Key bits: 256
  Signature Algorithm: ecdsa-with-SHA256
  Not valid before: 2023-11-01T00:00:00
  Not valid after:  2033-01-30T00:00:00
  MD5:   1a2b 3c4d 5e6f 7081 9200 a1b2 c3d4 e5f6
  SHA-1: 0011 2233 4455 6677 8899 aabb ccdd eeff 0011 2233
"""

H_SSH_ALGOS = """
  kex_algorithms: (5)
      curve25519-sha256
      curve25519-sha256@libssh.org
      ecdh-sha2-nistp256
      diffie-hellman-group-exchange-sha256
      diffie-hellman-group16-sha512
  server_host_key_algorithms: (3)
      rsa-sha2-512
      rsa-sha2-256
      ssh-ed25519
  encryption_algorithms: (4)
      chacha20-poly1305@openssh.com
      aes128-ctr
      aes256-gcm@openssh.com
      aes128-gcm@openssh.com
  mac_algorithms: (4)
      umac-64-etm@openssh.com
      umac-128-etm@openssh.com
      hmac-sha2-256-etm@openssh.com
      hmac-sha2-512-etm@openssh.com
  compression_algorithms: (2)
      none
      zlib@openssh.com
"""

H_SSH_HOSTKEY = """
  256 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 (ECDSA)
  256 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00 (ED25519)
  3072 ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89 (RSA)
"""

H_HTTP_METHODS = """
  Supported Methods: GET HEAD POST OPTIONS
"""

H_MONGODB = """
  ERROR: not authorized on admin to execute command { listDatabases: 1.0 }
"""

H_REDIS = """
  ERROR: NOAUTH Authentication required.
"""

H_SMB_SECURITY_MODE = """
  account_used: <blank>
  authentication_level: user
  challenge_response: supported
  message_signing: required
"""

H_SMB_PROTOCOLS = """
  dialects:
    2.0.2
    2.1
    3.0
    3.0.2
    3.1.1
"""

H_RDP = """
  Security layer
    CredSSP (NLA): SUCCESS
    CredSSP with Early User Auth: FAILED
    Native RDP: FAILED
    SSL: FAILED
  RDP Encryption level: High
"""

SAMPLE_HEALTHY_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -p- -oX healthy.xml 10.20.30.40" start="1704067200" startstr="Mon Jan  1 00:00:00 2024" version="7.94" xmloutputversion="1.05">
  <host starttime="1704067200" endtime="1704067400">
    <status state="up" reason="echo-reply" reason_ttl="64"/>
    <address addr="10.20.30.40" addrtype="ipv4"/>
    <hostnames><hostname name="www.example.com" type="PTR"/></hostnames>
    <ports>
      <extraports state="closed" count="65527"><extrareasons reason="resets" count="65527"/></extraports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="9.6" extrainfo="protocol 2.0" method="probed" conf="10"/>
{script("ssh2-enum-algos", H_SSH_ALGOS)}
{script("ssh-hostkey", H_SSH_HOSTKEY)}
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="https" product="nginx" version="1.24.0" tunnel="ssl" method="probed" conf="10"/>
{script("ssl-enum-ciphers", H_SSL_CIPHERS)}
{script("ssl-cert", H_SSL_CERT)}
{script("http-methods", H_HTTP_METHODS)}
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services" method="probed" conf="10"/>
{script("rdp-enum-encryption", H_RDP)}
      </port>
      <port protocol="tcp" portid="27017">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="mongodb" product="MongoDB" version="6.0.13" method="probed" conf="10"/>
{script("mongodb-databases", H_MONGODB)}
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="redis" product="Redis key-value store" version="7.2.4" method="probed" conf="10"/>
{script("redis-info", H_REDIS)}
      </port>
      <port protocol="tcp" portid="8081">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="mysql" method="table" conf="3"/>
      </port>
    </ports>
    <hostscript>
{script("smb-security-mode", H_SMB_SECURITY_MODE, indent="      ")}
{script("smb-protocols", H_SMB_PROTOCOLS, indent="      ")}
    </hostscript>
  </host>
  <runstats>
    <finished time="1704067400" timestr="Mon Jan  1 00:03:20 2024" elapsed="200.00" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""


def main() -> None:
    out = os.path.normpath(OUT)
    os.makedirs(out, exist_ok=True)
    for name, content in (
        ("sample.xml", SAMPLE_XML),
        ("sample.gnmap", SAMPLE_GNMAP),
        ("sample.nmap", SAMPLE_NMAP),
        ("sample-scripts.xml", SAMPLE_SCRIPTS_XML),
        ("sample-healthy.xml", SAMPLE_HEALTHY_XML),
    ):
        path = os.path.join(out, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content.lstrip("\n"))
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
