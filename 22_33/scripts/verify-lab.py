#!/usr/bin/env python3
"""Run real HTTP experiments against a running backend, using only disposable lab state."""
import base64
import json
import sys
import urllib.request

base = (sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080').rstrip('/')

def request(path, body=None, method='POST'):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + '/api/labs' + path, data=data, method=method,
                                 headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as response:
        raw = response.read()
        return json.loads(raw) if raw else None

created = request('')
session = '/' + created['sessionId']
keys = {identity['name']: identity for identity in created['identities']}

def call(action, body):
    return request(session + '/' + action, body)

def signed(owner='alice'):
    packet = call('prepare', {'senderId': 'alice', 'receiverId': 'bob', 'message': '  Exact café\nmessage  '})
    return call('sign', {'packet': packet, 'privateKey': keys[owner]['privateKey']})

def verify(packet):
    return call('verify', {'packet': packet, 'recipientId': 'bob'})

def deliver(packet, protection):
    return call('deliver', {'packet': packet, 'recipientId': 'bob', 'replayProtection': protection})

try:
    packet = signed()
    assert verify(packet)['signatureValid'] is True
    altered = dict(packet, message='modified without signing')
    assert verify(altered)['signatureValid'] is False
    print('PASS: exact content verifies; modified content fails')
    signature = bytearray(base64.b64decode(packet['signature']))
    signature[0] ^= 1
    assert verify(dict(packet, signature=base64.b64encode(signature).decode()))['signatureValid'] is False
    print('PASS: bit-flipped signature fails')
    forged = signed('mallory')
    assert verify(forged)['signatureValid'] is False
    call('trust', {'recipientId': 'bob', 'senderId': 'alice', 'publicKey': keys['mallory']['publicKey']})
    substituted = verify(forged)
    assert substituted['signatureValid'] is True and substituted['keyMatchesPinned'] is False
    print('PASS: impersonation fails with authentic key; substitution verifies but breaks pinned-key match')
    call('trust', {'recipientId': 'bob', 'senderId': 'alice', 'publicKey': ''})
    missing = verify(packet)
    assert missing['reason'] == 'NO_TRUSTED_KEY' and missing['signatureValid'] is None
    call('trust', {'recipientId': 'bob', 'senderId': 'alice', 'publicKey': keys['alice']['publicKey']})
    assert verify(packet)['signatureValid'] is True
    print('PASS: missing trust is reported separately; restoring key restores verification')
    assert deliver(packet, False)['accepted'] is True
    assert deliver(packet, False)['accepted'] is True
    replay = deliver(packet, True)
    assert replay['signatureValid'] is True and replay['reason'] == 'DUPLICATE_MESSAGE_ID' and replay['accepted'] is False
    second = signed()
    assert second['messageId'] != packet['messageId'] and deliver(second, True)['accepted'] is True
    print('PASS: replay accepted without protection; rejected with protection; new identical text accepted')
    state = request(session, method='GET')
    stored = state['inbox'][0]
    assert stored['packet']['message'] == packet['message']
    print('PASS: signed inbox record remains readable plaintext')
    request(session + '/inbox/' + stored['deliveryId'], altered)
    edited = request(session, method='GET')['inbox'][0]['packet']
    assert edited['signature'] == packet['signature'] and verify(edited)['signatureValid'] is False
    print('PASS: storage tampering preserves original signature and fails re-verification')
finally:
    request(session, method='DELETE')
