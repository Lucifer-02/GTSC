import socket
from base64 import b64encode


SERVER = "192.168.12.108"
PORT = 587
ADDR = (SERVER, PORT)

USERNAME = "hoang@localserver.com"
PASSWORD = "1"

FROM = "hoang@localserver.com"
TO = "minh@localserver.com"  # must be a list
SUBJECT = "alo"
TEXT = "Chao Minh dz"


# Create a client socket
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# Connect to the server
clientSocket.connect(ADDR)

# SMTP server responds
received = clientSocket.recv(2048)
print("received: ", received)

send = f"ehlo [{SERVER}]\r\n\0".encode()
clientSocket.send(send)
print("send: ", send)

received = clientSocket.recv(2048)
print("received: ", received)


send = f"AUTH LOGIN\r\n".encode()
clientSocket.send(send)
print("send: ", send)

# Receive data from server
received = clientSocket.recv(2048)
print("received: ", received)

# encrypt username and send
hash = b64encode(USERNAME.encode()).decode()
send = f"{hash}\r\n".encode()
clientSocket.send(send)
print("send: ", send)

# Receive data from server
received = clientSocket.recv(2048)
print("received: ", received)

# encrypt password and send
hash = b64encode(PASSWORD.encode()).decode()
send = f"{hash}\r\n".encode()
clientSocket.send(send)
print("send: ", send)

received = clientSocket.recv(2048)
print("received: ", received)

send = f'MAIL FROM:<{FROM}>\r\n'.encode()
clientSocket.send(send)
print("send: ", send)

received = clientSocket.recv(2048)
print("received: ", received)

send = f"RCPT TO:<{TO}>\r\n".encode()
clientSocket.send(send)
print("send: ", send)

received = clientSocket.recv(2048)
print("received: ", received)

send = 'DATA\r\n'.encode()
clientSocket.send(send)
print("send: ", send)

received = clientSocket.recv(2048)
print("received: ", received)

# lưu ý cần gửi dạng này vì thông tin FROM và TO đã gửi ở trên chỉ để cho phía server biết địa chỉ người gừi và nhận còn phía người dùng cần gửi riêng lần nữa, nếu không có FROM và TO thì message nhận được sẽ không có các trường này
send = f"From: {FROM}\r\nTo: {TO}\r\nSubject: {SUBJECT}\r\n\r\n{TEXT}\r\n.\r\n".encode()
clientSocket.send(send)
print("send: ", send)


received = clientSocket.recv(2048)
print("received: ", received)

send = 'QUIT\r\n'.encode()
clientSocket.send(send)
print("send: ", send)

# Receive data from server
received = clientSocket.recv(2048)
print("received: ", received)
