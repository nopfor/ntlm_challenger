
NTLM Challenger
===============

ntlm_challenger will send a NTLM negotiate message to a provided HTTP or SMB endpoint that accepts NTLM authentication, parse the challenge message, and print information received from the server.

Requirements
------------

ntlm_challenger supports Python 3.

The `requests` library is used to make HTTP(S) requests. `impacket` is used to set up the SMB connection.

Usage
-----

Send NTLM negotiate message to the provided URL and parse the challenge message.

```
python3 ntlm_challenger.py <URL>
```

HTTP Example:

```
$ python3 ntlm_challenger.py 'https://autodiscover.hackin.club/autodiscover/'

Target (Domain): HACKIN

Version: Server 2012 / Windows 8 (build 9200)

TargetInfo:
        MsvAvNbDomainName: HACKIN
        MsvAvNbComputerName: EXCH01
        MsvAvDnsDomainName: hackin.club
        MsvAvDnsComputerName: EXCH01.hackin.club
        MsvAvDnsTreeName: hackin.club
        MsvAvTimestamp: Nov 3, 2019 01:07:16.573170

Negotiate Flags:
        NTLMSSP_NEGOTIATE_UNICODE
        NTLMSSP_REQUEST_TARGET
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        NTLMSSP_TARGET_TYPE_DOMAIN
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        NTLMSSP_NEGOTIATE_TARGET_INFO
        NTLMSSP_NEGOTIATE_VERSION
```

SMB Example:

```
$ python3 ntlm_challenger.py 'smb://192.168.39.152'

Target (Server): DESKTOP-G1984A4

Version: Server 2016 or 2019 / Windows 10 (build 18362)

TargetInfo:
  MsvAvNbDomainName: DESKTOP-G1984A4
  MsvAvNbComputerName: DESKTOP-G1984A4
  MsvAvDnsDomainName: DESKTOP-G1984A4
  MsvAvDnsComputerName: DESKTOP-G1984A4
  MsvAvTimestamp: Mar 20, 2020 01:54:23.634713

Negotiate Flags:
  NTLMSSP_NEGOTIATE_UNICODE
  NTLMSSP_REQUEST_TARGET
  NTLMSSP_TARGET_TYPE_SERVER
  NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
  NTLMSSP_NEGOTIATE_TARGET_INFO
  NTLMSSP_NEGOTIATE_VERSION
  NTLMSSP_NEGOTIATE_128
  NTLMSSP_NEGOTIATE_56
```
