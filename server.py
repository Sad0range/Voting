from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
import sys
import socket
from datetime import datetime, timedelta
from select import select
 
SOCKET_LIST = []
SOCKET_SESSION = []
CLIENTS = []
RECV_BUFFER = 4096 
END_TIME = datetime.now() + timedelta(minutes = 20)

def setup():
    # server setup
    HOST = ''
    PORT = 9009

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)

    SOCKET_LIST.append(server_socket)

    print "Server started on port " + str(PORT)

    # secutity setup
    privatekey = RSA.generate(2048)
    publickey = privatekey.publickey()

    return server_socket, privatekey, publickey

def server():
    server_socket, privatekey, publickey = setup()

    while 1:
        ready_to_read,ready_to_write,in_error = select(SOCKET_LIST,[],[],0)
      
        for sock in ready_to_read:
            # a new connection request recieved
            if sock == server_socket: 
                sockfd, addr = server_socket.accept()
                SOCKET_LIST.append(sockfd)
                print "Client (%s, %s) connected" % addr
                sockfd.send(publickey.exportKey())
             
            # process data recieved from client, 
            else:
                try:
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        check_session_key = 0
                        for session_asc in SOCKET_SESSION:
                            if sock == session_asc[0]:
                                check_session_key = 1
                                sessionkey = session_asc[1]
                                proceed_data(sock, sessionkey, data)
                                break
                        if check_session_key == 0:
                            sessionkey = decrypt_rsa(sock, privatekey, data)
                            SOCKET_SESSION.append([sock, sessionkey])
                    else:  
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)
                            remove_session(sock)

                except:
                    continue

    server_socket.close()
 
def proceed_data(sock, sessionkey, ciphertext):
    plaintext = decrypt_session(sessionkey, ciphertext)
    words = plaintext.split(" ") 
    action = words[0]
    if action == "Reg":
        msg = registration(words)
    elif action == "Login":
        msg = authorization(words)
    msg = encrypt_session(sessionkey, msg)
    sock.send(msg)

def decrypt_rsa(sock, privatekey, ciphertext):
    cipherrsa = PKCS1_OAEP.new(privatekey)
    plaintext = cipherrsa.decrypt(ciphertext)
    return plaintext

def decrypt_session(sessionkey, ciphertext):
    iv = ciphertext[:16]
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    plaintext = obj.decrypt(ciphertext)
    plaintext = plaintext[16:]
    return plaintext

def encrypt_session(sessionkey, plaintext):
    iv = Random.new().read(16)
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    ciphertext = iv + obj.encrypt(plaintext)
    return ciphertext

def registration(data):
    if datetime.now() > END_TIME:
        return "reg_closed"

    login = data[1]
    password = data[2]

    for client_data in CLIENTS:
        if login == client_data[0]:
            return "invalid_log"

    uniq = get_key(login, password)
    vote_perm = 1
    lst = []
    CLIENTS.append([login, uniq, vote_perm, lst])

    return str(uniq)

def authorization(data):
    login = data[1]
    password = data[2]

    for client_data in CLIENTS:
        if login == client_data[0]:
            key = get_key(login, password)
            if key == client_data[1]:
                return str(key)
    return "invalid_log"

def get_key(login, password):
    return SHA.new(login + password).digest()

def remove_session(sock):
    dest = []
    for session in SOCKET_SESSION:
        if session[0] == sock:
            dest = session
            break
    SOCKET_SESSION.remove(dest)

if __name__ == "__main__":
    sys.exit(server())         