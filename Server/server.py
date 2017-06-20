import sys
import socket
from datetime import datetime, timedelta
from select import select
from security import *

def parse():
    cands = ""
    with open("Candidates.txt") as inf:
        text = inf.readlines()
    for line in text:
        cands += str(line.strip()) + " "

    return "bul " + cands, len(text)

SOCKET_LIST = []
SOCKET_SESSION = []
VOTE = []
CLIENTS = []
RECV_BUFFER = 4096 
CANDIDATES, NUM_OF_CANDIDATES = parse()
END_REG_TIME = datetime.now() + timedelta(seconds = 5)
END_VOTE_TIME = END_REG_TIME + timedelta(seconds = 2)

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

    privatekey, publickey = security_setup()

    return server_socket, privatekey, publickey

def server():
    server_socket, privatekey, publickey = setup()
    voting_flag = 1

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
                    ciphertext = sock.recv(RECV_BUFFER)
                    if ciphertext:
                        check_session_key = 0
                        for session_asc in SOCKET_SESSION:
                            if sock == session_asc[0]:
                                check_session_key = 1
                                sessionkey = session_asc[1]
                                proceed_data(sock, sessionkey, ciphertext)
                                break
                        if check_session_key == 0:
                            sessionkey = decrypt_rsa(sock, privatekey, ciphertext)
                            SOCKET_SESSION.append([sock, sessionkey])
                    else:  
                        if sock in SOCKET_LIST:
                            remove_session(sock)

                except:
                    continue

        if voting_flag == 1:
            if datetime.now() >= END_VOTE_TIME:
                voting_flag = 0
                msg = voting()
                for session in SOCKET_SESSION:
                    tmp = msg
                    tmp = encrypt_session(session[1], tmp)
                    session[0].send(tmp)
                print "Voting over"
            elif datetime.now() >= END_REG_TIME:
                send_bulletin()

    server_socket.close()
 
def proceed_data(sock, sessionkey, ciphertext):
    plaintext = decrypt_session(sessionkey, ciphertext)
    words = plaintext.split(" ") 
    action = words[0]
    if action == "Reg":
        msg = registration(words, sock)
    elif action == "Login":
        msg = authorization(words, sock)
    elif action == "Vote":
        msg = vote(words) 
    msg = encrypt_session(sessionkey, msg)
    sock.send(msg)

def registration(data, sock):
    if datetime.now() > END_REG_TIME:
        return "reg_closed"

    login = data[1]
    password = data[2]

    for client_data in CLIENTS:
        if login == client_data[0]:
            return "invalid_log"

    key = get_key(login, password)
    need_lst = 1
    lst = []

    print login + " has been registrated to vote"
    CLIENTS.append([login, need_lst, sock])
    VOTE.append([key, lst])

    return key

def authorization(data, sock):
    login = data[1]
    password = data[2]

    for client_data in CLIENTS:
        if login == client_data[0]:
            key = get_key(login, password)
            for vote_data in VOTE:
                if key == vote_data[0]:
                    print login + " logined"
                    if len(vote_data[1]) == 0:
                        client_data[1] = 1
                    else:
                       client_data[1] = 0
                    client_data[-1] = sock
                    msg = str(key)
                    return msg

    return "invalid_log"

def vote(data):
    key = data[1]
    values = data[2:]
    for vote_data in VOTE:
        if key == vote_data[0]:
            if len(vote_data[1]) == 0:
                vote_data[1] = values
                print key
                print vote_data[1]
                return "done"
            else:
                return "already"

    return "invalid"

def voting():
    c_list = CANDIDATES.strip().split(" ")[1:]
    msg = "res "
    result = [0] * NUM_OF_CANDIDATES
    for vote_data in VOTE:
        grades = vote_data[1]
        for i, grade in enumerate(grades):
            if grade != "*":
                result[i] += int(grade)
    for i in range(NUM_OF_CANDIDATES):
        msg += c_list[i*3] + " " + c_list[i*3+1] + " " + c_list[i*3+2] + " " + str(result[i]) + " "
    msg += "voters "
    for i in CLIENTS:
        msg += i[0] + " "

    return msg
        
def remove_session(sock):
    SOCKET_LIST.remove(sock)
    dest = []
    for session in SOCKET_SESSION:
        if session[0] == sock:
            dest = session
            break
    SOCKET_SESSION.remove(dest)
    for client_data in CLIENTS:
        if sock == client_data[-1]:
            client_data[-1] = -1
            print client_data[0] + " disconnected"

def send_bulletin():    
    for client_data in CLIENTS:
        if client_data[1]:
            client_data[1] = 0;
            sock = client_data[-1]
            if sock == -1:
                continue
            for session in SOCKET_SESSION:
                if sock == session[0]:
                    sessionkey = session[1]
                    break
            msg = encrypt_session(sessionkey, CANDIDATES)
            sock.send(msg)
            print "Bulletin send to " + client_data[0]

if __name__ == "__main__":
    sys.exit(server())         