from base64 import b64encode
import socket
import threading

PORT = 587
SERVER = "192.168.14.92"
ADDR = (SERVER, PORT)

# create socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# bind socket to port
s.bind(ADDR)

print('Waiting for connection...')

# create a function to handle the connection


def tcplink(sock, addr):
    print('Accept new connection from %s:%s...' % addr)

    sending = b'220 localhost ESMTP\r\n'
    sock.send(sending)
    print("sending: ", sending.decode())

    receiving = sock.recv(2048)
    print("Received: ", receiving)

    sending = b'250-localhost\r\n250-SIZE 20480000\r\n250-AUTH LOGIN\r\n250 HELP\r\n'
    sock.send(sending)
    print("sending: ", sending.decode())

    receiving = sock.recv(2048)
    print("Received: ", receiving)

    username = b64encode(b'Username:').decode()
    sending = f'334 {username}\r\n'
    print("sending: ", sending)
    sock.send(sending.encode())

    receiving = sock.recv(2048)
    print("Received: ", receiving)

    password = b64encode(b'Password:').decode()
    sending = f'334 {password}\r\n'
    print("sending: ", sending)
    sock.send(sending.encode())

    receiving = sock.recv(2048)
    print("Received: ", receiving)

    sending = b'235 authenticated.\r\n'
    sock.send(sending)
    print("sending: ", sending.decode())

    receiving = sock.recv(2048)
    print("Received: ", receiving)

    sending = b'250 OK\r\n'
    sock.send(sending)
    print("sending: ", sending.decode())

    receiving = sock.recv(2048)
    print("Received: ", receiving)

    sending = b'250 OK\r\n'
    sock.send(sending)
    print("sending: ", sending.decode())

    receiving = sock.recv(2048)
    print("Received: ", receiving)

    sending = b'354 OK, send.\r\n'
    sock.send(sending)
    print("sending: ", sending.decode())

    receiving = sock.recv(2048)
    print("Received: ", receiving)

    sending = b'250 Queued\r\n'
    sock.send(sending)
    print("sending: ", sending.decode())

    receiving = sock.recv(2048)
    print("Received: ", receiving)

    sending = b'221 goodbye\r\n'
    sock.send(sending)
    print("sending: ", sending.decode())

    sock.close()
    print('Connection from %s:%s closed.' % addr)


def start_server():
    s.listen()
    while True:
        # accept new connection
        sock, addr = s.accept()
        print(sock, addr)
        # create new thread to handle the connection
        t = threading.Thread(target=tcplink, args=(sock, addr))
        t.start()


if __name__ == '__main__':
    start_server()
