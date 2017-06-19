# chat_client.py

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
        self.registered = False

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
            print('\nUnable to connect.')
            sys.exit()

        print('\nConnected to voting server.')

    def generate_keys(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def set_personal_data(self, login, password):
        self.login = login
        self.password = password

        print('login:', login)
        print('pass :', password)

    def get_server_public_key(self):
        public_key_recieved = False
        while not public_key_recieved:
            socket_list = [self.server_socket]
            # Get the list sockets which are readable
            ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])
             
            for sock in ready_to_read:
                if sock == self.server_socket:
                    # incoming message from remote server, server_socket
                    data = self.server_socket.recv(4096)

                    if not data:
                        print('\nDisconnected from server.')
                        sys.exit()

                    self.server_public_key = RSA.importKey(data)
                    public_key_recieved = True
                    print('\nServer public key recieved.')

    def generate_session_key(self):
        self.session_key = Random.new().read(32)
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
        self.encrypted_session_key = cipher_rsa.encrypt(self.session_key)

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

    def send_personal_data_to_server(self):
        text = str(self.login) + str(self.password)
        msg = self.encrypt(text)
        
        self.server_socket.send(self.encrypted_session_key)
        self.server_socket.send(msg)

        print('\nPersonal data sent.')

    def get_regisration_result(self, data):
        registration_result_recieved = False
        while not registration_result_recieved:
            socket_list = [self.server_socket]
            # Get the list sockets which are readable
            ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])
             
            for sock in ready_to_read:
                if sock == self.server_socket:
                    data = self.server_socket.recv(4096)

                    if not data:
                        print('\nDisconnected from server.')
                        sys.exit()

                    text = self.decrypt(data)
                    
                    if text == 'Login already exists':
                        print('Please, select another login and password.')
                        login = input('Login:')
                        password = input('Password:')
                        self.set_personal_data(login, password)
                    else:
                        self.registered = True
                    registration_result_recieved = True

    def registre(self):
        self.get_server_public_key()
        self.send_personal_data_to_server()
        self.get_regisration_result()
        
 
def voter():
    if(len(sys.argv) < 3) :
        sys.exit()

    login = sys.argv[1]
    password = sys.argv[2]

    if(len(login) != 4 or len(password) != 6):
        print('Invalid login or password:\n')
        print('login: 4 symbols')
        print('password: 6 symbols')

    client = Client()
    client.connect()

    client.set_personal_data(login, password)    
    client.generate_session_key()
    client.registre()


if __name__ == "__main__":

    sys.exit(voter())
