from keepcrypt import keepcrypt

from os import listdir
from os.path import isfile, isdir
from os.path import join

def files(path):
    try:
        if isdir(path):
            return [f for f in listdir(path) if isfile(join(path, f))]
    except:
        pass
    return []

from nacl.signing import VerifyKey
from nacl.public import PrivateKey, SealedBox, PublicKey
from nacl.utils import random

from threading import Thread, Lock
from Queue import Queue

import socket

PACK_SIZE = 1201
MEET = 0

class ClientWorkerPool(Thread):
    _public_keys = []
    _nonces = []
    _clients = []
    _task_queue = Queue()
    _results = {}
    def __init__(self, public_keys, nonces, count=5): 
        self._public_keys = public_keys
        self._nonces = nonces
        for x in range(count+1):
            self._clients.append(ClientWorker())

    def get(self, public_key):
        pass
    
    def add(self, public_key, verify_key, nonce):
        if nonce in self._nonces or public_key in self._public_keys:
            return False
        return True

    def run(self):
        while True:
            task = self._task_queue.get()
            if type(task) == tuple:
                cmd = task[0]
                args = task[1:]
                client = None
                while client is None:
                    for may_client in self._clients:
                        if may_client.locked:
                            continue
                        client = may_client
                        break
                func = getattr(client, cmd, None)()

class ClientWorker(Thread):
    _lock = Lock()
    _lock_bool = False

    @property
    def locked(self):
        return self._lock_bool
    
    def get(self, public_key):
        self._lock.acquire()
        self._lock_bool = True
        self._lock_bool = False
        self._lock.release()

    def add(self, public_key, verify_key):
        self._lock.acquire()
        self._lock_bool = True
        client_file = open(join("clients", public_key), "w+")
        client_file.write(verify_key)
        client_file.close()
        self._lock_bool = False
        self._lock.release()

class ClientHandle(Thread):
    def __init__(addr, port, data, privat, sign, init_socket):
        # Socket
        self.__closed = False
        self.__init_socket = init_socket
        self.__sock = self.__init_socket()
        # Client Data
        self.__addr = addr
        self.__port = port
        self.__init_data = data
        # Crypto
        self.__sprivat = SealedBox(privat)
        self.__sprivsign = sign
        # Meta Data
        self.__cpublic = None
        self.__cpubsign = None

    def __resolve(public_key):
        if not public_key in files("clients"):
            return False
        self.__cpubsign = VerifyKey(open(join("clients", public_key)).read().decode('ascii'), encoder=nacl.encoding.HexEncoder)
        self.__cpublic = PublicKey(public_key, encoder=nacl.encoding.HexEncoder)
        return True

    @property
    def _cid():
        return self.__cid

    def __soft_decrypt(data):
        data = self.__sprivat.decrypt(data)
        req_id = int(data[:1])
        return data, req_id

    def _full_decrypt(data):
        data, req_id = __soft_decrypt(data)
        public_key = data[1089:1153].decode('ascii')
        signature = data[1025:1089]
        pack = data[1:1025]
        if not self.__resolve(public_key):
            return False
        verify_key.verify(signature)
        return pack, req_id

    def _accessable(addr, port, public_key=None, more=None):
        return True
    
    def _handle(req_id, pack):
        pass

    def _send(data):
        if self.__sock.proto == socket.SOCK_STREAM and self.__closed == True:
            self.__sock = self.__init_socket()
        if self.__cpublic is None:
            # backfall to keepcrypt just trying to resolve txt records over dnscrypt resolver config with addr as field name
            # never fall back to a unencrypted solution
            # this is needed for a radical never unencrypted connection point of view
            # this is not only paranoid version is a moral version
            public_keys = keepcrypt.resolve_pubs(self.__addr)
            verify_keys = keepcrypt.resolve_verifies(self.__addr)

            max_len = len(public_keys)
            if max_len < len(verify_keys):
                max_len = len(verify_keys)

            for x in range(max_len):
                if x >= len(verify_keys) or x >= len(public_keys):
                    continue
                public_key = public_keys[x]
                verify_key = verify_keys[x]
                pk = PublicKey(public_key, encoder=nacl.encoding.HexEncoder)
                vk = VerifyKey(verify_key, encoder=nacl.encoding.HexEncoder)
                signed = vk.sign(data)
                self.__sock.sendto(self.__sprivat.encrypt(signed), (self.__port, self.__addr))
            return
        self.__sock.sendto(self.__cpublic, (self.__port, self.__addr))

    def run():
        if not self._accessable(self.__addr, self.__port):
            self.radical_close()
            return
        
        data, req_id = self.__soft_decrypt(self.__init_data)
        if req_id == MEET:
            verify_key = data[1:65].decode('ascii')
            public_key = data[65:129].decode('ascii')
            more = data[129:1153]
            if (not self._accessable(self.__addr, self.__port, public_key=public_key, more=more)) or (not verify_key.isalnum()) or (not public_key.isalnum()) or public_key in files("clients"):
                self.radical_close()
                return

            client_file = open(join("clients", public_key), "w+")
            client_file.write(verify_key)
            client_file.close()
            
            self._send(bytes(int(1))+bytes(self.__sprivsign.verify_key.encode(encoder=nacl.encoding.HexEncoder)))
            self.close()
            return
        else:
            args = _full_decrypt(self.__init_data)
            if type(args) != tuple:
                self.radical_close()
                return
            pack, req_id = args
            self._handle(req_id, pack)

    # never forget to close the current process
    # mostly you can do this with return
    def radical_close():
        self._send(bytes(int(0)))
        self.close()

    def close():
        if self.__sock.proto == socket.SOCK_STREAM:
            self.__sock.close()
            self.__closed = True

class Server(Thread):
    def __init__(host='127.0.0.1', port=1337, tcp=False):
        pass

    def run():
        pass
        