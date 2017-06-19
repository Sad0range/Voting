from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import sys
import socket
from select import select
 
SOCKET_LIST = []
SOCKET_SESSION = []
CLIENTS = []
RECV_BUFFER = 4096 

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
             
            else:
                # process data recieved from client, 
                try:
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        check_session_key = 0
                        for session_asc in SOCKET_SESSION:
                            if sock == session_asc[0]:
                                check_session_key = 1
                                plaintext = decrypt_session(session_asc[1], data)
                                msg = registration(plaintext)
                                msg = encrypt_session(session_asc[1], msg)
                                sock.send(msg)
                        if check_session_key == 0:
                            get_session_key(sock, privatekey, data)
                    else:  
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)

                except:
                    continue

    server_socket.close()
 
def get_session_key(sock, privatekey, data):
    cipherrsa = PKCS1_OAEP.new(privatekey)
    sessionkey = cipherrsa.decrypt(data)
    SOCKET_SESSION.append([sock, sessionkey])

def decrypt_session(sessionkey, ciphertext):
    iv = ciphertext[:16]
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    plaintext = obj.decrypt(ciphertext)
    plaintext = plaintext[16:]
    return plaintext

def encrypt_session(sessionkey, plaintext):
    iv = Random.new().read(16) # 128 bit
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    ciphertext = iv + obj.encrypt(plaintext)
    return ciphertext

def registration(data):
    login = data[:4]

    for client_data in CLIENTS:
        if login == client_data[0]:
            return "Login already exists"

    password = data[4:10]
    uniq = authorization(login, password)
    CLIENTS.append([login, uniq])

    return "Registration done:\n" + str(uniq)

def authorization(login, password):
    return "lox-" + str(login)[:2] + str(password)[2:]

if __name__ == "__main__":
    sys.exit(server())         