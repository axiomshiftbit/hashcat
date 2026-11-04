#!/usr/bin/env python3
"""Generate deterministic, synthetic offline converter fixtures."""
import argparse
import gzip
import hashlib
import hmac
from pathlib import Path
import shutil
import struct
import subprocess


def pcap(path, packets, link=1):
    data = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
    for index, packet in enumerate(packets):
        data += struct.pack('<IIII', 1700000000 + index, 0, len(packet), len(packet)) + packet
    path.write_bytes(data)


def pcapng(source, destination):
    raw = source.read_bytes()
    link = struct.unpack_from('<I', raw, 20)[0]
    data = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    data += struct.pack('<IIHHII', 1, 20, link, 0, 65535, 20)
    offset = 24
    while offset < len(raw):
        seconds, microseconds, caplen, length = struct.unpack_from('<IIII', raw, offset)
        offset += 16
        packet = raw[offset:offset + caplen]
        offset += caplen
        packet += bytes((-caplen) % 4)
        size = 32 + len(packet)
        stamp = seconds * 1000000 + microseconds
        data += struct.pack('<IIIIIII', 6, size, 0, stamp >> 32, stamp & 0xFFFFFFFF, caplen, length)
        data += packet + struct.pack('<I', size)
    destination.write_bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--hash2cap', default=shutil.which('hcxhash2cap'))
    args = parser.parse_args()
    if not args.hash2cap:
        parser.error('hcxhash2cap is required')
    root = args.directory
    root.mkdir(parents=True, exist_ok=True)
    ssid = b'GUI-Fixture-Network'
    password = b'gui-fixture-only'
    ap, sta = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    pmk = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, 32)
    pmkid = hmac.new(pmk, b'PMK Name' + ap + sta, 'sha1').digest()[:16]
    old = '*'.join(item.hex() for item in (pmkid, ap, sta, ssid))
    (root / 'synthetic.16800').write_text(old + '\n')
    (root / 'expected-pmkid.txt').write_text('WPA*01*' + old + '***\n')
    subprocess.run([args.hash2cap, '--pmkid=' + str(root / 'synthetic.16800'), '-c', str(root / 'synthetic.cap')], check=True, stdout=subprocess.DEVNULL)
    shutil.copyfile(root / 'synthetic.cap', root / 'synthetic.pcap')
    pcapng(root / 'synthetic.cap', root / 'synthetic.pcapng')
    (root / 'synthetic.pcap.gz').write_bytes(gzip.compress((root / 'synthetic.cap').read_bytes(), mtime=0))

    anonce, snonce = bytes(range(1, 33)), bytes(range(33, 65))
    key_data = bytes.fromhex('30140100000fac040100000fac040100000fac020000')
    body = bytes([2]) + struct.pack('>HHQ', 0x010A, 16, 1) + snonce + bytes(16 + 8 + 8 + 16) + struct.pack('>H', len(key_data)) + key_data
    eapol = b'\x02\x03' + struct.pack('>H', len(body)) + body
    message = b'Pairwise key expansion\0' + min(ap, sta) + max(ap, sta) + min(anonce, snonce) + max(anonce, snonce)
    ptk = b''.join(hmac.new(pmk, message + bytes([i]), 'sha1').digest() for i in range(4))[:64]
    mic = hmac.new(ptk[:16], eapol, 'sha1').digest()[:16]
    hccapx = struct.pack('<IIBB', 0x58504348, 4, 0, len(ssid)) + ssid.ljust(32, b'\0')
    hccapx += bytes([2]) + mic + ap + anonce + sta + snonce + struct.pack('<H', len(eapol)) + eapol.ljust(256, b'\0')
    assert len(hccapx) == 393
    (root / 'synthetic.hccapx').write_bytes(hccapx)
    hccap = ssid.ljust(36, b'\0') + ap + sta + snonce + anonce + eapol.ljust(256, b'\0') + struct.pack('<II', len(eapol), 2) + mic
    assert len(hccap) == 392
    (root / 'synthetic.hccap').write_bytes(hccap)

    def eap(code, kind, payload):
        packet = bytes([code, 7]) + struct.pack('>H', len(payload) + 5) + bytes([kind]) + payload
        header = struct.pack('<HH', 0x0208 if code == 1 else 0x0108, 0)
        header += (sta + ap if code == 1 else ap + sta) + ap + b'\0\0'
        return header + b'\xaa\xaa\x03\x00\x00\x00\x88\x8e\x02\x00' + struct.pack('>H', len(packet)) + packet

    challenge = bytes(range(16))
    response = hashlib.md5(bytes([7]) + password + challenge).digest()
    pcap(root / 'eap-md5.pcap', [eap(1, 4, b'\x10' + challenge), eap(2, 4, b'\x10' + response)], 105)
    pcap(root / 'eap-leap.pcap', [eap(1, 17, b'\x01\x00\x08' + bytes(range(8)) + b'fixture'), eap(2, 17, b'\x01\x00\x18' + bytes(range(1, 25)) + b'fixture')], 105)

    session = bytes.fromhex('12345678')
    plain = b'\x01\x01\x01\x01\x00\x00\x00\x01x'
    pad = hashlib.md5(session + password + b'\xc0\x01').digest()
    ciphertext = bytes(a ^ b for a, b in zip(plain, pad))
    tacacs = b'\xc0\x01\x01\x00' + session + struct.pack('>I', len(ciphertext)) + ciphertext
    tcp = struct.pack('>HHIIHHHH', 49152, 49, 1, 1, 0x5018, 65535, 0, 0) + tacacs
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + tcp
    pcap(root / 'tacacs.pcap', [sta + ap + b'\x08\x00' + ip])
    (root / 'dictionary.txt').write_bytes(password + b'\n')
    print('Synthetic capture fixtures generated.')


if __name__ == '__main__':
    main()
