#!/usr/bin/env python3

# parsing from "NT LAN Manager (NTLM) Authentication Protocol" v20190923, revision  31.0
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/%5bMS-NLMP%5d.pdf

import argparse

import requests
import sys
import base64
import datetime

from collections import OrderedDict


def decode_string(byte_string):
  return byte_string.decode('UTF-8').replace('\x00', '')

def decode_int(byte_string):
  return int.from_bytes(byte_string, 'little')


def parse_version(version_bytes):
  
  major_version = version_bytes[0]
  minor_version = version_bytes[1]
  product_build = decode_int(version_bytes[2:4])

  version = 'Unknown'

  if major_version == 5 and minor_version == 1:
    version = 'Windows XP (SP2)'
  elif major_version == 5 and minor_version == 2:
    version = 'Server 2003'
  elif major_version == 6 and minor_version == 0:
    version = 'Server 2008 / Windows Vista'
  elif major_version == 6 and minor_version == 1:
    version = 'Server 2008 R2 / Windows 7'
  elif major_version == 6 and minor_version == 2:
    version = 'Server 2012 / Windows 8'
  elif major_version == 6 and minor_version == 3:
    version = 'Server 2012 R2 / Windows 8.1'
  elif major_version == 10 and minor_version == 0:
    version = 'Server 2016 or 2019 / Windows 10'

  return '{} (build {})'.format(version, product_build)


def parse_negotiate_flags(negotiate_flags_int):

  flags = OrderedDict()

  flags['NTLMSSP_NEGOTIATE_UNICODE']                  = 0x00000001
  flags['NTLM_NEGOTIATE_OEM']                         = 0x00000002
  flags['NTLMSSP_REQUEST_TARGET']                     = 0x00000004
  flags['UNUSED_10']                                  = 0x00000008
  flags['NTLMSSP_NEGOTIATE_SIGN']                     = 0x00000010
  flags['NTLMSSP_NEGOTIATE_SEAL']                     = 0x00000020
  flags['NTLMSSP_NEGOTIATE_DATAGRAM']                 = 0x00000040
  flags['NTLMSSP_NEGOTIATE_LM_KEY']                   = 0x00000080
  flags['UNUSED_9']                                   = 0x00000100
  flags['NTLMSSP_NEGOTIATE_NTLM']                     = 0x00000400
  flags['UNUSED_8']                                   = 0x00000400
  flags['NTLMSSP_ANONYMOUS']                          = 0x00000800
  flags['NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED']      = 0x00001000
  flags['NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED'] = 0x00002000
  flags['UNUSED_7']                                   = 0x00004000
  flags['NTLMSSP_NEGOTIATE_ALWAYS_SIGN']              = 0x00008000
  flags['NTLMSSP_TARGET_TYPE_DOMAIN']                 = 0x00010000
  flags['NTLMSSP_TARGET_TYPE_SERVER']                 = 0x00020000
  flags['UNUSED_6']                                   = 0x00040000
  flags['NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY'] = 0x00080000
  flags['NTLMSSP_NEGOTIATE_IDENTIFY']                 = 0x00100000
  flags['UNUSED_5']                                   = 0x00200000
  flags['NTLMSSP_REQUEST_NON_NT_SESSION_KEY']         = 0x00400000
  flags['NTLMSSP_NEGOTIATE_TARGET_INFO']              = 0x00800000
  flags['UNUSED_4']                                   = 0x01000000
  flags['NTLMSSP_NEGOTIATE_VERSION']                  = 0x02000000
  flags['UNUSED_3']                                   = 0x10000000
  flags['UNUSED_2']                                   = 0x08000000
  flags['UNUSED_1']                                   = 0x04000000
  flags['NTLMSSP_NEGOTIATE_128']                      = 0x20000000
  flags['NTLMSSP_NEGOTIATE_KEY_EXCH']                 = 0x40000000
  flags['NTLMSSP_NEGOTIATE_56']                       = 0x80000000

  negotiate_flags = []

  for name,value in flags.items():
    if negotiate_flags_int & value:
      negotiate_flags.append(name)

  return negotiate_flags


def parse_target_info(target_info_bytes):

  MsvAvEOL             = 0x0000
  MsvAvNbComputerName  = 0x0001
  MsvAvNbDomainName    = 0x0002
  MsvAvDnsComputerName = 0x0003
  MsvAvDnsDomainName   = 0x0004
  MsvAvDnsTreeName     = 0x0005
  MsvAvFlags           = 0x0006
  MsvAvTimestamp       = 0x0007
  MsvAvSingleHost      = 0x0008
  MsvAvTargetName      = 0x0009
  MsvAvChannelBindings = 0x000A

  target_info = OrderedDict()
  info_offset = 0

  while info_offset < len(target_info_bytes):
    av_id = decode_int(target_info_bytes[info_offset:info_offset+2])
    av_len = decode_int(target_info_bytes[info_offset+2:info_offset+4])
    av_value = target_info_bytes[info_offset+4:info_offset+4+av_len]
    
    info_offset = info_offset + 4 + av_len
    
    if av_id == MsvAvEOL:
      pass
    elif av_id == MsvAvNbComputerName:
      target_info['MsvAvNbComputerName'] = decode_string(av_value)
    elif av_id == MsvAvNbDomainName:
      target_info['MsvAvNbDomainName'] = decode_string(av_value)
    elif av_id == MsvAvDnsComputerName:
      target_info['MsvAvDnsComputerName'] = decode_string(av_value)
    elif av_id == MsvAvDnsDomainName:
      target_info['MsvAvDnsDomainName'] = decode_string(av_value)
    elif av_id == MsvAvDnsTreeName:
      target_info['MsvAvDnsTreeName'] = decode_string(av_value)
    elif av_id == MsvAvFlags:
      pass
    elif av_id == MsvAvTimestamp:
      filetime = decode_int(av_value)
      microseconds = (filetime - 116444736000000000) / 10
      time = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds = microseconds)
      target_info['MsvAvTimestamp'] = time.strftime("%b %d, %Y %H:%M:%S.%f")
    elif av_id == MsvAvSingleHost:
      target_info['MsvAvSingleHost'] = decode_string(av_value)
    elif av_id == MsvAvTargetName:
      target_info['MsvAvTargetName'] = decode_string(av_value)
    elif av_id == MsvAvChannelBindings:
      target_info['MsvAvChannelBindings'] = av_value

  return target_info


def parse_challenge(challenge_message):

  # Signature
  signature = decode_string(challenge_message[0:7]) # b'NTLMSSP\x00' --> NTLMSSP

  # MessageType
  message_type = decode_int(challenge_message[8:12]) # b'\x02\x00\x00\x00' --> 2

  # TargetNameFields
  target_name_fields  = challenge_message[12:20]
  target_name_len     = decode_int(target_name_fields[0:2])
  target_name_max_len = decode_int(target_name_fields[2:4])
  target_name_offset  = decode_int(target_name_fields[4:8])

  # NegotiateFlags
  negotiate_flags_int = decode_int(challenge_message[20:24])

  negotiate_flags = parse_negotiate_flags(negotiate_flags_int)

  # ServerChallenge
  server_challenge = challenge_message[24:32]

  # Reserved
  reserved = challenge_message[32:40]

  # TargetInfoFields
  target_info_fields  = challenge_message[40:48]
  target_info_len     = decode_int(target_info_fields[0:2])
  target_info_max_len = decode_int(target_info_fields[2:4])
  target_info_offset  = decode_int(target_info_fields[4:8])

  # Version
  version_bytes = challenge_message[48:56]
  version = parse_version(version_bytes)

  # TargetName
  target_name = challenge_message[target_name_offset:target_name_offset+target_name_len]
  target_name = decode_string(target_name)

  # TargetInfo
  target_info_bytes = challenge_message[target_info_offset:target_info_offset+target_info_len]

  target_info = parse_target_info(target_info_bytes)

  return {
    'target_name': target_name,
    'version': version,
    'target_info': target_info,
    'negotiate_flags': negotiate_flags
  }


def print_challenge(challenge):

  if 'NTLMSSP_TARGET_TYPE_DOMAIN' in challenge['negotiate_flags']:
    print('\nTarget (Domain): {}'.format(challenge['target_name']))
  elif 'NTLMSSP_TARGET_TYPE_SERVER' in challenge['negotiate_flags']:
    print('\nTarget (Server): {}'.format(challenge['target_name']))

  print('\nVersion: {}'.format(challenge['version']))

  print('\nTargetInfo:')
  
  for name,value in challenge['target_info'].items():
    print('  {}: {}'.format(name, value))

  print('\nNegotiate Flags:')

  for flag in challenge['negotiate_flags']:
    print('  {}'.format(flag))


def main():

  # setup arguments
  parser = argparse.ArgumentParser(description='Fetch and parse NTLM challenge ' +
    'messages from HTTP (e.g. Autodiscover/ActiveSync/OWA) services')
  parser.add_argument('url', help='URL to fetch NTLM challenge from')
  args = parser.parse_args()
  
  # setup request
  headers = {'Authorization': 'NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA='}
  request = requests.get(args.url, headers=headers)
  
  if request.status_code not in [401, 302]:
    print('[!] Expecting response code 401 or 302, received: {}'.format(request.status_code))
    sys.exit()
  
  # get auth header
  auth_header = request.headers.get('WWW-Authenticate')
  
  if not auth_header:
    print('[!] NTLM Challenge response not found (WWW-Authenticate header missing)')
    sys.exit()

  if not 'NTLM' in auth_header:
    print('[!] NTLM Challenge response not found (WWW-Authenticate does not contain "NTLM")')
    sys.exit()

  # get challenge message from header
  challenge_message = base64.b64decode(auth_header.split(' ')[1].replace(',', ''))

  # parse challenge
  challenge = parse_challenge(challenge_message)

  # print challenge
  print_challenge(challenge)


if __name__ == '__main__':
  main()
