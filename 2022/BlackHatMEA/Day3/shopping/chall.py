#!/usr/local/bin/python
#
# Polymero
#

# Imports
import os
import random
from time import time
from hashlib import sha256
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse
from Crypto.Cipher import AES

# Global parameters
VER = '3.14'

#------------------------------------------------------------------------------------------------------------------
# DiffieChat Server Class
#------------------------------------------------------------------------------------------------------------------
class DiffieServer:
    #--------------------------------------------------------------------------------------------------------------
    # Initialise Server
    def __init__(self):
        # Enryption paramters
        self.g = 2
        self.p = getPrime(1024)
        # Databases
        self.__client_database = {}
        self.__groups_database = {}
    #--------------------------------------------------------------------------------------------------------------
    # Register new client
    def register(self, name: str):
        if name in [self.__client_database[i]['name'] for i in self.__client_database]:
            print('|  ~ ERROR :: Username already taken.')
            return
        new_Client = Client(self, name)
        self.__client_database[new_Client.key_ID] = {
            'obj'    : new_Client,
            'name'   : new_Client.name,
            'key_ID' : new_Client.key_ID,
            'pk'     : new_Client.pk
        }
        return new_Client
    #--------------------------------------------------------------------------------------------------------------
    # Register new group chat
    def register_group(self, key_ID: str, pk: int, members: list):
        self.__groups_database[key_ID] = {
            'key_ID'  : key_ID,
            'pk'      : pk,
            'members' : members
        }
        return self.__groups_database[key_ID]
    #--------------------------------------------------------------------------------------------------------------    
    # Show all registered clients (public information)
    def show_clients(self):
        if self.__client_database == {}:
            print('|\n|  ~ No registered clients.\n|')
        else:
            print('|\n|  ~ List of registered clients ::\n|')
            for i in self.__client_database:
                cl = self.__client_database[i]
                print('|  ~ {} ::\n|    usr_id = {}\n|    usr_pk = {}\n|  '.format(cl['name'],cl['key_ID'],cl['pk'])) 
    #--------------------------------------------------------------------------------------------------------------
    # Show all registered groups (public information)
    def show_groups(self):
        if self.__groups_database == {}:
            print('|\n|  ~ No registered groups.\n|')
        else:
            print('|\n|  ~ List of registered groups:\n|')
            for i in self.__groups_database:
                gr = self.__groups_database[i]
                print('|  ~ {} ::\n|    grp_id = {}\n|    grp_pk = {}\n|  '.format([i.name for i in gr['members']],gr['key_ID'],gr['pk']))
    #--------------------------------------------------------------------------------------------------------------
    # Request public key
    def request(self, key_ID: str):
        if key_ID in self.__client_database:
            return self.__client_database[key_ID]['pk']
        if key_ID in self.__groups_database:
            return self.__groups_database[key_ID]['pk']
        print('|  ~ ERROR :: ID not recognised.')
    #--------------------------------------------------------------------------------------------------------------
    # Request identification of key ID
    def identify(self, key_ID: str):
        if key_ID in self.__client_database:
            return 'Client', self.__client_database[key_ID]['name']
        if key_ID in self.__client_database:
            return 'Group', self.__client_database[key_ID]['name']
        print('|  ~ ERROR :: ID not recognised.')
    #--------------------------------------------------------------------------------------------------------------
    # Handle packet send to the server
    def handle_packet(self, packet: str):
        sendr_ID, recip_ID = packet.split(':')[-2:]
        if recip_ID in self.__client_database:
            self.__client_database[recip_ID]['obj'].recv(packet)
            self.__client_database[sendr_ID]['obj'].recv(packet)
        elif recip_ID in self.__groups_database:
            for m in self.__groups_database[recip_ID]['members']:
                m.recv(packet)
        else:
            print('|  ~ ERROR :: Unknown Recipient ID.')
#------------------------------------------------------------------------------------------------------------------
# END OF CLASS STRUCTURE
#------------------------------------------------------------------------------------------------------------------ 


#------------------------------------------------------------------------------------------------------------------
# Client Class
#------------------------------------------------------------------------------------------------------------------
class Client:
    # Identification variables
    name   = None
    key_ID = None
    # Diffie-Hellman variables
    pk     = None
    __sk   = None
    # Chat dictionary
    chats  = None
    #--------------------------------------------------------------------------------------------------------------
    # Initialise client 
    def __init__(self, SRV: DiffieServer, name: str):
        self.Server = SRV
        # Key Generation
        self.__sk = random.randint(2, self.Server.p)
        self.pk   = pow(self.Server.g, self.__sk, self.Server.p)
        # Identification
        self.name   = name
        self.key_ID = sha256((self.name + str(self.pk) + 'DiffieChat Ver {}'.format(VER)).encode()).hexdigest()
        # Chats
        self.chats = {}
    #--------------------------------------------------------------------------------------------------------------
    # Create a new chat    
    def create_chat(self, mems: list, name: str = None):      
        if (len(mems) < 2) or any([type(m) != Client for m in mems]):
            print('|  ~ ERROR :: Not a valid group.')
        else:
            members = mems
            if len(mems) == 2:
                other  = [m for m in members if m != self][0]
                key_ID = other.key_ID
                self.chats[key_ID] = {
                    'chat_obj' : Chat(self.Server),
                    'members'  : [m.name for m in members],
                    'name'     : other.name,
                    'enc_type' : "1-to-1 E2EE",
                    'key_ID'   : key_ID,
                    'pk'       : other.pk,
                    'sk'       : pow(other.pk, self.__sk, self.Server.p),
                    'unread'   : 0
                }
                other.join(members, self.name, self.key_ID, self.pk, self.chats[key_ID]['sk'])
            elif len(mems) > 2:
                others   = [m for m in members if m != self]
                group_pk = random.randint(2, self.Server.p)
                group_sk = pow(self.Server.g, group_pk, self.Server.p)
                key_ID   = sha256((name + str(members) + str(group_pk) + 'DiffiChat Ver {}'.format(VER)).encode()).hexdigest()
                self.chats[key_ID] = {
                    'chat_obj' : Chat(self.Server),
                    'members'  : [m.name for m in members],
                    'name'     : name,
                    'enc_type' : "1-to-N E2EE",
                    'key_ID'   : key_ID,
                    'pk'       : group_pk,
                    'sk'       : group_sk,
                    'unread'   : 0
                }
                for m in others:
                    m.join(members, name, key_ID, group_pk, group_sk)
                return self.Server.register_group(key_ID, group_pk, members)
    #--------------------------------------------------------------------------------------------------------------
    # Join a chat
    def join(self, members: list, name: str, key_ID: str, group_pk: int, group_sk: int):
        if len(members) == 2:
            enc_type = "1-to-1 E2EE"
        else:
            enc_type = "1-to-N E2EE"
        self.chats[key_ID] = {
                    'chat_obj' : Chat(self.Server),
                    'members'  : [m.name for m in members],
                    'name'     : name,
                    'enc_type' : enc_type,
                    'key_ID'   : key_ID,
                    'pk'       : group_pk,
                    'sk'       : group_sk,
                    'unread'   : 0
                }
    #--------------------------------------------------------------------------------------------------------------
    # Leave a chat
    def leave(self, name: str):
        del self.chats[name]
    #--------------------------------------------------------------------------------------------------------------
    # Show all available status
    def show_chats(self):
        if self.chats == {}:
            print('|  ~ No available chats.')
        else:
            print('|\n|  ~ List of active chats ::\n|')
            for i in self.chats:
                ch = self.chats[i]
                print('|  [{}] {} ::\n|      member = {}\n|      enctyp = {}\n|      key_id = {}\n|      key_pk = {}\n|'.format(
                      ch['unread'], ch['name'], ch['members'], ch['enc_type'], ch['key_ID'], ch['pk']))
    #--------------------------------------------------------------------------------------------------------------
    # Send a message to a chat
    def send(self, key_ID: str, msg: str):
        self.__encrypt(msg, self.chats[key_ID]['sk'], key_ID)
        self.chats[key_ID]['unread'] -= 1
    #--------------------------------------------------------------------------------------------------------------
    # Receive a packet
    def recv(self, packet):
        sendr_ID, recip_ID = packet.split(':')[-2:]
        if recip_ID in self.chats:
            cht = self.chats[recip_ID]
            dec = self.__decrypt(packet, self.chats[recip_ID]['sk'])
        elif sendr_ID in self.chats:
            cht = self.chats[sendr_ID]
            dec = self.__decrypt(packet, self.chats[sendr_ID]['sk'])
        else:
            print('|  ~ ERROR :: Unknown packet received.')
        cht['chat_obj'].add(packet, dec)
        cht['unread'] += 1
    #--------------------------------------------------------------------------------------------------------------
    # Read a chat
    def read(self, key_ID):   
        1
    #--------------------------------------------------------------------------------------------------------------
    # E2EE Encryption Scheme
    def __encrypt(self, msg: str, secret: int, recip_ID: str):
        if type(msg) == str:
            msg = msg.encode()
        # Get message parameters
        msg   = msg.replace(b':',b'')
        while len(msg) % 16 != 0:
            msg += b' '
        salt   = os.urandom(8)
        # Get encryption parameters
        Ke     = sha256('{:02x}:{}:{}'.format(int(secret), salt.hex(), 'Key').encode()).digest()
        IVpre  = sha256('{:02x}:{}:{}'.format(int(secret), salt.hex(), 'IV').encode()).digest()
        IVe    = long_to_bytes(bytes_to_long(IVpre[:16]) ^ bytes_to_long(IVpre[16:]))
        # Cipher text
        C      = AES.new(Ke, AES.MODE_CBC, IVe).encrypt(msg)
        # Authentication
        V      = sha256(C).digest()
        Tpre   = long_to_bytes(bytes_to_long(V[:16]) ^ bytes_to_long(V[16:]))
        T      = AES.new(Ke, AES.MODE_ECB).encrypt(Tpre)
        # Create packet (to send to the server)
        packet = '{}:{}:{}:{}:{}:{}:{}'.format('DiffieChat Ver {}'.format(VER), int(time()), salt.hex(), C.hex(), T.hex(), self.key_ID, recip_ID)
        self.Server.handle_packet(packet)
    #--------------------------------------------------------------------------------------------------------------
    # E2EE Decryption Scheme
    def __decrypt(self, packet: str, secret: int):
        # Separate elements
        ver, tim, salt, C, T, sendr_ID, recip_ID = packet.split(':')
        # Get decryption parameters
        Ke    = sha256('{:02x}:{}:{}'.format(int(secret), salt, 'Key').encode()).digest()
        IVpre = sha256('{:02x}:{}:{}'.format(int(secret), salt, 'IV').encode()).digest()
        IVe   = long_to_bytes(bytes_to_long(IVpre[:16]) ^ bytes_to_long(IVpre[16:]))
        # Authentication
        V     = sha256(bytes.fromhex(C)).digest()
        Tpre  = long_to_bytes(bytes_to_long(V[:16]) ^ bytes_to_long(V[16:]))
        Auth  = AES.new(Ke, AES.MODE_ECB).encrypt(Tpre)
        if Auth.hex() != T:
            print('|  ~ ERROR :: Invalid Authentication')
        else:
            # Plain text
            P = AES.new(Ke, AES.MODE_CBC, IVe).decrypt(bytes.fromhex(C))
            while P[-1] == ord(' '):
                P = P[:-1]
            return {
                'MSG' : P.decode(),
                'UTS' : int(tim),
                'SID' : self.Server.identify(sendr_ID)[1]
            }            
#------------------------------------------------------------------------------------------------------------------
# END OF CLASS STRUCTURE
#------------------------------------------------------------------------------------------------------------------ 


#------------------------------------------------------------------------------------------------------------------
# Chat Class
#------------------------------------------------------------------------------------------------------------------
class Chat:
    # Chat variables
    __packets = None
    __history = None
    #--------------------------------------------------------------------------------------------------------------
    # Initialise chat
    def __init__(self, SRV: DiffieServer):
        self.Server    = SRV
        self.__packets = []
        self.__history = []
    #--------------------------------------------------------------------------------------------------------------
    # Add to the chat
    def add(self, packet: str, msg: dict):
        self.__packets += [packet]
        self.__history += [msg]
    #--------------------------------------------------------------------------------------------------------------
    # Read the chat
    def read(self, n=10):
        return self.__packets[-n:], self.__history[-n:]       
#------------------------------------------------------------------------------------------------------------------
# END OF CLASS STRUCTURE
#------------------------------------------------------------------------------------------------------------------ 