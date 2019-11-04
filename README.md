
NTLM Challenger
===============

ntlm_challenger will send a NTLM negotiate message to a provided HTTP endpoint that accepts NTLM authentication, parse the challenge message, and print information received from the server.

Requirements
------------

ntlm_challenger supports Python 3.

Usage
-----

Send NTLM negotiate message over HTTP(S) to the provided URL and parse the challenge message.

```
python3 ntlm_challenger.py <URL>
```

Example:

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
