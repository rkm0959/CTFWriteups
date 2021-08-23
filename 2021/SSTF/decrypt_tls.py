from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa
import requests
import scipy.stats
import matplotlib.pyplot as plt
import abc
from dataclasses import dataclass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from handshake_headers import (
     HandshakeHeader,
    HANDSHAKE_HEADER_TYPES,
    HandshakeFinishedHandshakePayload,
    NewSessionTicketHandshakePayload,
)
from server_hello import ServerHello, RecordHeader
from client_hello import ClientHello, ExtensionKeyShare, ExtensionPreSharedKey, ExtensionEarlyData
from change_cipher_suite import ChangeCipherSuite
def hsh(x):
    return hashlib.sha256(x).digest()

def xor_iv(iv, num):
    formatted_num = (b"\x00" * 4) + struct.pack(">q", num)
    return bytes([i ^ j for i, j in zip(iv, formatted_num)])

@dataclass
class HandshakeKeys:
    client_key: bytes
    client_iv: bytes
    client_handshake_traffic_secret: bytes
    server_key: bytes
    server_iv: bytes
    server_handshake_traffic_secret: bytes
    handshake_secret: bytes

@dataclass
class ApplicationKeys:
    client_key: bytes
    client_iv: bytes
    server_key: bytes
    server_iv: bytes
    master_secret: bytes

def HKDF_Expand_Label(
    key, label, context, length, backend=default_backend(), algorithm=hashes.SHA256()
):
    tmp_label = b"tls13 " + label.encode()
    hkdf_label = (
        struct.pack(">h", length)
        + struct.pack("b", len(tmp_label))
        + tmp_label
        + struct.pack("b", len(context))
        + context
    )
    return HKDFExpand(
        algorithm=algorithm, length=length, info=hkdf_label, backend=backend
    ).derive(key)

def derive(shared_secret: bytes, hello_hash: bytes):#, resumption_keys: ResumptionKeys=None):
    backend = default_backend()
    # if resumption_keys:
    #     early_secret = resumption_keys.early_secret
    # else:
    early_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"\x00",
        salt=b"\x00",
        backend=backend,
    )._extract(b"\x00" * 32)
    
    empty_hash = hashlib.sha256(b"").digest()
    derived_secret = HKDF_Expand_Label(
        key=early_secret,
        algorithm=hashes.SHA256(),
        length=32,
        label="derived",
        context=empty_hash,
        backend=backend,
    )
    handshake_secret = HKDF(
        algorithm=hashes.SHA256(),
        salt=derived_secret,
        info=None,
        backend=backend,
        length=32,
    )._extract(shared_secret)
    print("handshake_secret", handshake_secret)
    client_handshake_traffic_secret = HKDF_Expand_Label(
        context=hello_hash,
        length=32,
        algorithm=hashes.SHA256(),
        label="c hs traffic",
        backend=backend,
        key=handshake_secret,
    )
    server_handshake_traffic_secret = HKDF_Expand_Label(
        context=hello_hash,
        algorithm=hashes.SHA256(),
        length=32,
        label="s hs traffic",
        backend=backend,
        key=handshake_secret,
    )
    client_handshake_key = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        length=16,
        context=b"",
        label="key",
        backend=backend,
        key=client_handshake_traffic_secret,
    )
    server_handshake_key = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        length=16,
        context=b"",
        label="key",
        backend=backend,
        key=server_handshake_traffic_secret,
    )
    client_handshake_iv = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        length=12,
        context=b"",
        label="iv",
        backend=backend,
        key=client_handshake_traffic_secret,
    )
    server_handshake_iv = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        length=12,
        context=b"",
        label="iv",
        backend=backend,
        key=server_handshake_traffic_secret,
    )

    return HandshakeKeys(
        client_key=client_handshake_key,
        client_iv=client_handshake_iv,
        client_handshake_traffic_secret=client_handshake_traffic_secret,
        server_key=server_handshake_key,
        server_iv=server_handshake_iv,
        server_handshake_traffic_secret=server_handshake_traffic_secret,
        handshake_secret=handshake_secret,
    )

def derive_application_keys(handshake_secret: bytes, handshake_hash: bytes):
    empty_hash = hashlib.sha256(b"").digest()
    backend = default_backend()
    derived_secret = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=handshake_secret,
        label="derived",
        context=empty_hash,
        length=32,
    )
    master_secret = HKDF(
        info=b"\x00",
        salt=derived_secret,
        length=32,
        algorithm=hashes.SHA256(),
        backend=backend,
    )._extract(b"\x00" * 32)
    client_application_traffic_secret = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=master_secret,
        label="c ap traffic",
        context=handshake_hash,
        length=32,
    )
    server_application_traffic_secret = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=master_secret,
        label="s ap traffic",
        context=handshake_hash,
        length=32,
    )
    client_application_key = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=client_application_traffic_secret,
        label="key",
        context=b"",
        length=16,
    )
    server_application_key = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=server_application_traffic_secret,
        label="key",
        context=b"",
        length=16,
    )
    client_application_iv = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=client_application_traffic_secret,
        label="iv",
        context=b"",
        length=12,
    )
    server_application_iv = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=server_application_traffic_secret,
        label="iv",
        context=b"",
        length=12,
    )

    return ApplicationKeys(
        client_key=client_application_key,
        client_iv=client_application_iv,
        server_key=server_application_key,
        server_iv=server_application_iv,
        master_secret=master_secret
    )


from io import BytesIO, BufferedReader
from wrapper import Wrapper

global handshake_recv_counter
handshake_recv_counter = 0

def parse_wrapper(bytes_buffer : BufferedReader, HandShakeKey):
    global handshake_recv_counter
    wrapper = Wrapper.deserialize(bytes_buffer)
    if wrapper.record_header.size > len(wrapper.payload):
        wrapper.payload += bytes_buffer.read(wrapper.record_header.size - len(wrapper.payload))
    recdata = wrapper.record_header.serialize()
    authtag = wrapper.auth_tag

    ciphertext = wrapper.encrypted_data

    decryptor = AES.new(
        HandShakeKey.server_key,
        AES.MODE_GCM,
        xor_iv(HandShakeKey.server_iv, handshake_recv_counter),
    )
    decryptor.update(recdata)

    plaintext = decryptor.decrypt(bytes(ciphertext))
    handshake_recv_counter += 1

    decryptor.verify(authtag)
    return bytes_buffer, plaintext[:-1]

clienthello = bytes.fromhex('16030100c2010000be0303000000000000000000000000000000000000000000000000000000000000000000000c13011302c02bc02cc02fc0300100008900000013001100000e7777772e676f6f676c652e636f6d000a000400020017000b0002010000230000000d00080006040308040401002b0005040304030300330047004500170041046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
serverhello = bytes.fromhex('160303007b02000077030334e2af2f7c45ae218aecc7dcee69147f7add13970df54bae0f8c5fe40c58bfb900130100004f0033004500170041044c498978adb0dbdff8435373188f1dc1bb6cb00bd4ddc4e666bb6be71f0acae0678c2fbe5b188849324b45e5102c80423dcc6d62c19acdbefab83e8922048852002b00020304')

# may need to remove 02
DHE = '4c498978adb0dbdff8435373188f1dc1bb6cb00bd4ddc4e666bb6be71f0acae0'

rand1 = '0000000000000000000000000000000000000000000000000000000000000000'
rand2 = '34e2af2f7c45ae218aecc7dcee69147f7add13970df54bae0f8c5fe40c58bfb9'
totserverhello = '82e71c107c3c2dd5d4f756e9ed66af54a406d1ffc8ad031c3579dc3d71523aac845e9e6d2a211283f9e963bb89a2f8ad16c4cdc431ba0fa2448b79868673c5d57619fa46e5d2f8b62dd2babaf6b42365d5164ed4d4fc7814bbeb6ad4a5df779120191da7a4299feb2c92ec7ff5feab49f634b89446c36e797f32cd71638c50f72d98f7bdd64bcbc45447828ef27fa53376c10d3cf489a0059ef1083d87e5d64bbadeced011aa88123a8549840415d35e1e27cb9fc34f9fa4f2cd2ec4dc30be2c631d305a02c8b4ef4b72d26c4fceb0fcf8582a11d2193642505c6e36974dba6fa4d845b71eaf3598b5026d25e892b86242fddd5f63ec81de433450c9e98bac0a52a12a9523ee6a81cdad2c524cc9539ac4af52991d171338373282fbd3953270716350d92470534839cbaf4620aee861f79a0285e2e79a27ec011efbf3c0fe3c6a6facac877a53138399865535fa146b829f47d0b47f3bd652b7d8fa9ac51cc1f7df67048156c4aa71f18566326e6e362709265fff55f1e7b5269347ec1c024950a436ed45c11a9dd509245a77b43d6d5e341a5b5b219d98112e1ade052d70700ffa2e5d08b446f99f3a0f25de4b98aaa7f1e8a497bc427a24bb8203589b65ce2f3e1592d0ceb55cfd4fcfd836c97c39f4229a63781729b0fe60c507bab91074c856bcf4ae1d71dade8c81bdc1bcacb7a690722125e82670cb539fba2436a2660e6f1e54f27006b8d2b3b14795a8d4ae27d6e978d5eb586d5fe2ae687064ff9e30ec42f66a2760b60a883cdfdc3a8dcddc7a1d60be5e5b5fd895e880b82dc1dd4209a2d498b1fbd92dc48752f0b951636147f49db4b6660acb5287906edcb1e129309dcd85a00ee3ba32b3d7e94435a2160f282eb6605272a1a43602bd68a93fd4ebf01ec8242768a8de037bd3155e4e34da44781f402aaf784931d9d0ba2c93bd42e0a5834869c20917eca4796bee35cbf102a1586608550f8dd4a8ef391526cbf0e955b27197575836b56d8b63fb5196bbc85fb0030007840ea8f9f90bb6a4487e719a6a76259023e5cae2b8230a2e87fa23fe05b12992fb9ecabed4db23ed8e410f948895ba73f9d3f3ccf0f99d7f38d80bbc044fc672dcd028d7a46ca4e50024aa85b28557f8dc233d0799fd5b3a1ce181f3761867b358a2000795f3b23b145827eb3c14ffbd3aed95e244581691ea9991656fa9d1e6c87349286565e49f86a8f024b81f295a8e3a35360242cbc3307e756ae751cf138fe65705753fd191b7e789acd8cb5502c520a9169e2a32358453e8802c7e64086d5f3a2a09fa7136626dd30861b20fafc313fc347509fb1bbd3ef39870ff243238ef29296688bd582282335bbbed7648e2bcf719255a2831c6801086a5784c780e25ce7f52de8ce19ae75796cc52285fb0fe8a348cc707e8b47496bad6f407de0eec812d87c5322c99861c5c2bcaf916786581651b0ecae03970da91bbf7f229c1c3a2ab9f0245310118f809c1af74a4a029681595d91f601defd0cb3a03fd5575b4b0ff4cb12d40f5808b6317ccdbcea21e7b161ef8a97e72d6fc2b0dc4461879f2b668725258d5cc35071711a525950317851f82612c431212dc5363e0bdeeb6a973b4d0523bcbba90921ed1ee1c1f9c3c0130b8a2566c0a8a9636a22188607d5b139fc07c9297cc6b9552fa900b7fef1ac77445fd9bd8a0136c32d1b4e30c7997515cc9319ba3a18ea61513e8b6e85cfec565106eb72fd0172bec92877dfe6009c05db6682f1378f5cb53c6de34e7af501c75e640b25dfc7040cb1728331bf167d82cd14d202aae1db3cdd67155639f255b99dabc416f409251616ea0e991f792bf50cbebc2500e604d60d38e35b50da3cf711bc3d8174afc5fd95250f57c784a4755bcaf961de52ae4f68ab128f6161d2e5631d55ba10ca443d4080f0368e306a7959f3a8bd391bbccbafc603b271e75e190a0a48961243065c8f5dba55cad0852ac6f6a2873c7c7af41da54bef6be271a9bdecb086a278597fcbcc0e055b394d4fe2d8ca1ef8725b66d76b5760cf98545e76bb570b404595b3e7184cbdc174bae09634a84a8b1db02f28f670b0ec97ce45914c7fb49edc7d3c8686eed6a4eed3502c86a1a96e6c3369ce5982da233bbf3cf38340403a45ebfb6ab822bc4e1024d43ec0220bc1201d9aa3c336add8308be4edeae2bf97f8d4d4596bdaae1977a2a886dd1a86912f93056e344420c385c113df9dcc98b056c71d0853208c9f415debc4c141a23b6d234f9cfb4ac672f033a39e6f364b882538f5bd0e06a6a74ae04847299d751c83121f5ed2af690b4b3f41457880b68a9e508c28b81a8a75c9b90dcd8c3b2ea18c4627665c1085620ac81322d0e18bab0581d485f677cb56b371e41479a5cf01c80a0038a960e415a972cee7e0c3a6d82735bc1032949b40dff7f50a710b3d441b35afdd4783737e8304ab6e0bd6564aaa13c8438a165837cca159ba36ecad3d03530b15f8641f0dd62d287ce52d9262359113629bf238bcd9c66a2eed76ec95fed3073715ff748fa4a642fdaf2373397c8db987884180c1ed49f1aed9d30a88505636ad6ddafe9f70dd9d8fc586bacd116deee86b13cb0aa58206fe767c2f46d7d5e4d3e2d3c248cd6377078313586f13bac6ade2af7b61f0b1637a9627b26741f3d03b6a4af7e80c5d7d345063955fc83aeb6c0d88b09f9a28c50764934082be9bb197f1a0398488f05e60611844d65df854a3fe8fd9f7ad02e208430b687c5dc056e8bfe42502bae4ebab8d42b74e1ef2f532c5039171aaaacbd2a18d6ca7efc142cbda3a08d3ab9acdabc932dc4a130e85c7e08df4045027feaaf7b367715c2ebbe515e27250706ce651b5022571cafad139ac4fffe08f5f2a230e1804958d65a287e6714bf74293ad6a29ce29c9d4afb2318d3d62cd8dffe36ac8aceecd477772ee94007d53f5767c14346f582caaa5bb4e905c75ea0daea9c3ca0513cd651e4347a022ba5c3bfdc27e4c8b1e4d6ce17fd4d753dd34e4af67ef79733cac7bfac6193d0a28f2e5d938d61362dc0fa021c95bf0cc6a2ecc4dee7a3ddb24e40e90bfdd037f3b920a16d164f9a3e015c06f0eb62fb58a57655f006b29a537df7e549017afbe0ba42fa6b2e986b8c95b13a3dded61845b7ce8317ebaa46fcf664553acafddf7f12cdee9617fe75eab6148d2cabd508a0c82353b1c025efba558a9526e0fe1e9e8b124bd26f6a5d2c85032b5f48f55477da47008ca2ce789732983ce6600db7470d0efebb7731321015be7a1d4f6618ac0b3cd8449da6a65d19497ec1f799121744a6b661dc77fb3294cf075f605df1f27f80a593d29689c45aa560d3fd6a657faa5e809f52ecfc2b8d38f471c6547fff822313d98f941fd1bbf92f52face29149448c04697b6a0f92be3cdbb5451d6fd18c54bfacfd1d924d242018b22782e03f6fd8d809c2168260954c6f8b42a6d09654f85de7e87b089124f0577ace1e6181ad41ec9784bf322939f8b592ee4'
data = '94aac92027a5485a1f3b7014750fd6b8a133074a9f5acb548461380e2cf2f9f7ec4f22ad0d9d01ba3771e014f1ed12b141093cc6aa'

data = '13c975c5a0bb8d6f65bbffc993249babf103c1b08c4a25e0686c23b036ea0499c6234b5ec6bbb8cb479468ed4ae84e9cacd66240e63b221fa0e472e12c14b831b5258fe0af6c1257fa3d395bcb0fa1f49788724a291a97d40648e1a8cb09f4f47598b12908dd51af8e680401739cac787988d8e865357fcfb38a627a8afce78a20cc7a4cd2a995d10876ded40e8a2eb3493c39270cffae0c508fe6c47029a46ca3eb145cf39b2bd1ef58cf9b9f383e984dad52adc141064b8c7b20114e9e66cf55bd428db817538dfd20319864c50c94470cd95cd4757f7302f494c5c8db38ecc8b117931deb9e557c567e'
totserverhello = bytes.fromhex(totserverhello)
data = bytes.fromhex(data)

# send_client_hello
hello_hash_bytes = clienthello[5: ]


# shared secret
shared_secret = bytes.fromhex(DHE)


bytes_buffer = BufferedReader(BytesIO(serverhello))
original_buffer = bytes_buffer.peek()
sh = ServerHello.deserialize(bytes_buffer)
hello_hash_bytes += original_buffer[5 : sh.record_header.size + 5]

# calculate handshake keys
hello_hash = hsh(hello_hash_bytes)
handshakekeys = derive(shared_secret, hello_hash)


# plaintext
bytes_buffer = BufferedReader(BytesIO(b"\x17\x03\x03\x09\xb5" + totserverhello)) # maybe tot?


plaintext = bytearray()

bytes_buffer, resplaintext = parse_wrapper(bytes_buffer, handshakekeys)
plaintext += resplaintext
plaintext_buffer = BufferedReader(BytesIO(plaintext))

while True:
    if len(plaintext_buffer.peek()) < 4:
        bytes_buffer, res = parse_wrapper(bytes_buffer, handshakekeys)
        plaintext += res
        plaintext_buffer = BufferedReader(
            BytesIO(plaintext_buffer.peek() + res)
        )
    hh = HandshakeHeader.deserialize(plaintext_buffer.read(4))
    hh_payload_buffer = plaintext_buffer.read(hh.size)
    while len(hh_payload_buffer) < hh.size:
        bytes_buffer, res = parse_wrapper(bytes_buffer, handshakekeys)
        plaintext += res
        plaintext_buffer = BufferedReader(
            BytesIO(plaintext_buffer.peek() + res)
        )

        prev_len = len(hh_payload_buffer)
        hh_payload_buffer = hh_payload_buffer + plaintext_buffer.read(
            hh.size - prev_len
        )
    hh_payload = HANDSHAKE_HEADER_TYPES[hh.message_type].deserialize(
        hh_payload_buffer
    )
    if type(hh_payload) is HandshakeFinishedHandshakePayload:
        break

# print(plaintext)
hello_hash_bytes += plaintext

handshake_hash = hsh(hello_hash_bytes)

application_keys = derive_application_keys(handshakekeys.handshake_secret, handshake_hash)

clkey = application_keys.client_key
cliv = application_keys.client_iv

cipher = AES.new(key = clkey, mode = AES.MODE_GCM, nonce = cliv)
print(cipher.decrypt(data))
