from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from random import randint

DEBUG = 1

import sys
import socket
import select

# default parameters
host = '192.168.1.16'
#host = 'localhost'
port = 9009


class Client:
    def __init__(self):
        self.login = 0
        self.password = 0
        self.identificator = 0
        self.registrated = False
        self.authorized = False

        self.server_public_key = 0
        self.session_key = 0
        self.encrypted_session_key = 0

        self.server_socket = 0

        self.candidates_list = []

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

    def send_session_key(self):
        self.server_socket.send(self.encrypted_session_key)

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

        if DEBUG: print('Registration answer: <%s>' % text)
                    
        if text == 'invalid_log':   # login already exists
            return False

        elif text == 'reg_closed':
            print('Registration time expired.')
            sys.exit()

        else:   # text is unique hash-identificator
            self.authorized = True
            self.identificator = text
            print('Successfully signed.')
            return True


    def registre(self):
        action = 'Reg'
        text = action + ' ' + str(self.login) + ' ' + str(self.password)
        msg = self.encrypt(text)

        if DEBUG: print('reg text: <%s>' % text)

        self.server_socket.send(msg)

        return self.get_server_answer()

    def authorize(self):
        action = 'Login'
        text = action + ' ' + str(self.login) + ' ' + str(self.password)
        msg = self.encrypt(text)

        print('Auth text: <%s>' % text)
        
        self.server_socket.send(msg)

        return self.get_server_answer()

    def listen(self):
        while 1:
            data = self.wait_for_package()
            if not data:
                print('Disconnected from server.')

            data = self.decrypt(data)

            if data[:3] == 'res':
                self.get_result(data)
            if data[:3] == 'bul':
                self.get_bulletin(data)
                self.vote_automatically()

    def get_bulletin(self, text):
        text = text[4:].split(' ')
        for i in range(len(text) / 3):
            candidate = [text[i * 3], text[i * 3 + 1], text[i * 3 + 2]]
            self.candidates_list.append(candidate)
        for candidate in self.candidates_list:
            print(candidate)

    def get_result(self, text):
        print('Result recieved')
        text = text[4:]
        text = text.split(' voters ')
        result = text[0].split(' ')
        voters_list = text[1].split(' ')
        result_list = []

        for i in range(len(result) / 4):
            result_list.append(result[i*4 : i*4 + 4])
        print('Results:')
        for candidate in result_list:
            print(candidate)
        print('Voters:')
        for person in voters_list:
            print(person)

    def vote_automatically(self):
        votes = ['5', '4', '3', '2', '*']
        action = 'Vote'
        vote_list = ''
        for candidate in self.candidates_list:
            vote_list += ' ' + votes[randint(0, len(votes) - 1)]

        msg = action + ' ' + self.identificator + vote_list

        if DEBUG: print('vote <%s>' % msg)

        msg = self.encrypt(msg)
        self.server_socket.send(msg)

        confirmation = self.wait_for_package()
        confirmation = self.decrypt(confirmation)
        print('Confirmation <%s>' % confirmation)


def check_params(arg1, arg2, arg3):
    valid_params = True
    first_param_values = ['reg', 'log']

    if not arg1 in first_param_values:
        print('Invalid action selected')
        valid_params = False
    if len(arg2) < 2 or len(arg3) < 2:
        print('Login and password must be 2 symbols at least.')
        valid_params = False

    return valid_params

def get_params():
    acton = raw_input('reg(sign up) / log(sign in):')
    login = raw_input('Login:')
    password = raw_input('Password:')
    return action, login, password

def voter():
    action = 0
    login = 0
    password = 0

    if(len(sys.argv) == 4) :
        action = sys.argv[1]
        login = sys.argv[2]
        password = sys.argv[3]
    else:
        action,login,password = get_params()

    while not check_params(action, login, password):
        action, login, password = get_params()
    
    client = Client()
    client.connect()

    client.get_server_public_key() 
    client.generate_session_key()
    client.send_session_key()

    # authorization
    while not client.authorized:
        client.set_personal_data(login, password)

        if(action == 'reg'):
            if not client.registre():
                print('Login already exist.')
        elif(action == 'log'):
            if not client.authorize():
                print('Invalid login or password.')

        # re-enter action and params
        if not client.authorized:
            action, login, password = get_params()
            while not check_params(action, login, password):
                action, login, password = get_params()

    # voting
    
    client.listen()

if __name__ == "__main__":

    sys.exit(voter())