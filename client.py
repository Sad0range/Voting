from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random

DEBUG = 0

import sys
import socket
import select

# default parameters
host = '192.168.1.16'
#host = 'localhost'
port = 9009


class Client:
    def __init__(self):
        self.private_key = 0
        self.public_key = 0
        self.login = 0
        self.password = 0
        self.identificator = 0
        self.registrated = False
        self.authorized = False

        self.server_public_key = 0
        self.session_key = 0
        self.encrypted_session_key = 0

        self.server_socket = 0

    def connect(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.settimeout(2)

        # connect to remote host
        try :
            self.server_socket.connect((host, port))
        except :
            print('Unable to connect.')
            sys.exit()

        print('Connected to voting server.')

    def generate_keys(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def set_personal_data(self, login, password):
        self.login = login
        self.password = password

    def wait_for_package(self):
        package_recieved = False
        while not package_recieved:
            socket_list = [self.server_socket]
            # Get the list sockets which are readable
            ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])
             
            for sock in ready_to_read:
                if sock == self.server_socket:
                    # incoming message from remote server, server_socket
                    data = self.server_socket.recv(4096)
                    if not data:
                        print('Disconnected from server.')
                        sys.exit()
                    return data

    def get_server_public_key(self):
        print('Waiting for server public key.')
        data = self.wait_for_package();
        self.server_public_key = RSA.importKey(data)
        public_key_recieved = True
        print('Server public key recieved.')

    def generate_session_key(self):
        self.session_key = Random.new().read(32)
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
        self.encrypted_session_key = cipher_rsa.encrypt(self.session_key)
        #print('session key:')
        #print(self.session_key)

    def encrypt(self, text):
        iv = Random.new().read(16)
        obj = AES.new(self.session_key, AES.MODE_CFB, iv)
        ecnrypted_text = iv + obj.encrypt(text)
        return ecnrypted_text

    def decrypt(self, data):
        iv = data[:16]
        obj = AES.new(self.session_key, AES.MODE_CFB, iv)
        text = obj.decrypt(data)
        text = text[16:]
        return text

    def get_server_answer(self):
        print('Waiting server to answer...')

        data = self.wait_for_package()
        text = self.decrypt(data)

        print('Registration answer: <%s>' % text)
                    
        if text == 'invalid_log':   # login already exists
            print('Please, select another login.')
            login = raw_input('Login:')
            password = raw_input('Password:')
            self.set_personal_data(login, password)
        elif text == 'reg_closed':
            print('Registration time expired.')
            sys.exit()
        else:   # text is unique hash-identificator
            self.registrated = True
            self.authorized = True
            self.identificator = text


    def registre(self):
        action = 'Reg'
        text = action + ' ' + str(self.login) + ' ' + str(self.password)
        msg = self.encrypt(text)

        print('reg text: <%s>' % text)

        self.server_socket.send(self.encrypted_session_key)
        self.server_socket.send(msg)

        self.get_server_answer()

    def authorize(self):
        action = 'Login'
        text = action + ' ' + str(self.login) + ' ' + str(self.password)
        msg = self.encrypt(text)

        print('Auth text: <%s>' % text)
        
        self.server_socket.send(self.encrypted_session_key)
        self.server_socket.send(msg)

        self.get_server_answer()

    def listen(self):
        while 1:
            data = self.wait_for_package()
            data = self.decrypt(data)
            print(data)

    def vote(self):
        return 1
        
 
def voter():
    if(len(sys.argv) == 4) :
        action = sys.argv[1]
        login = sys.argv[2]
        password = sys.argv[3]
    else:
        acton = raw_input('reg(sign up) / log(sign in):')
        login = raw_input('Login:')
        password = raw_input('Password:')

    client = Client()
    client.connect()

    client.get_server_public_key() 
    client.generate_session_key()

    print('\taction:', action)
    print('\tlogin:', login)
    print('\tpass :', password)
    client.set_personal_data(login, password)
    if(action == 'reg'):
        while not client.registrated:
            client.registre()
    elif(action == 'log'):
        while not client.authorized:
            client.authorize()
    else:
        print('Invalid action selected.')
    client.listen()

if __name__ == "__main__":

    sys.exit(voter())