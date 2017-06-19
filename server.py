from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import sys
import socket
from select import select
 
SOCKET_LIST = []
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
                        cipherrsa = PKCS1_OAEP.new(privatekey)
                        raw = cipherrsa.decrypt(data)
                        client_publickey = RSA.importKey(raw[10:])
                        cipherrsa = PKCS1_OAEP.new(client_publickey)
                        msg = registration(data)
                        msg = cipherrsa.encrypt(client_publickey)    
                        sock.send(msg)    
                    else:  
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)

                except:
                    continue

    server_socket.close()
 
def registration(data):
    login = data[:4]

    for client_data in CLIENTS:
        if login == client_data[0]:
            return "Login already exists"

    password = data[4:10]
    uniq = authorization(login, password)
    key = data[10:]
    CLIENTS.append([login, uniq, key])

    return "Registration complete"

def authorization(login, password):
    return int(login) + int(password)

if __name__ == "__main__":
    sys.exit(chat_server())         