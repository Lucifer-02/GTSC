import socket
import re

<<<<<<< HEAD
SERVER = "192.168.12.65"
PORT = 21
ADDR = (SERVER, PORT)

USERNAME = "doanh"
PASSWORD = "doanh"
=======
SERVER = "127.0.0.1"
PORT = 21
ADDR = (SERVER, PORT)

USERNAME = "hoang"
PASSWORD = "hoang"
>>>>>>> 9df2cc6 (pull)

# Create a client socket
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
clientSocket.connect(ADDR)

# Receive the welcome message from the server
welcomeMessage = clientSocket.recv(1024).decode()
<<<<<<< HEAD
# Receive the response from the server
print(welcomeMessage)

# Send the username to the server
clientSocket.send(f"USER {USERNAME}\r\n".encode())

=======

# Send the username to the server
clientSocket.send(f"USER {USERNAME}\r\n".encode())
    
>>>>>>> 9df2cc6 (pull)
# Receive the response from the server
response = clientSocket.recv(1024).decode()
print(response)

# Send the password to the server
clientSocket.send(f"PASS {PASSWORD}\r\n".encode())

# Receive the response from the server
response = clientSocket.recv(1024).decode()
print(response)

<<<<<<< HEAD
=======
# Send the command to the server
clientSocket.send("CWD /\r\n".encode())

# Receive the response from the server
response = clientSocket.recv(1024).decode()
print(response)

>>>>>>> 9df2cc6 (pull)

# Send the command to the server
clientSocket.send("TYPE A\r\n".encode())

# Receive the response from the server
response = clientSocket.recv(1024).decode()
print(response)

# Send the command to the server
clientSocket.send("PASV\r\n".encode())

# Receive the response from the server
response = clientSocket.recv(1024).decode()
print(response)

# calculate the port number
match_object = re.search(r"\(\d+,\d+,\d+,\d+,(\d+),(\d+)\)", response)
dataPort = int(match_object.group(1)) * 256 + int(match_object.group(2))

# Send the command to the server
clientSocket.send("STOR file.txt\r\n".encode())

# Receive the response from the server
response = clientSocket.recv(1024).decode()
print(response)


# create a new socket to connect to the data port
dataSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dataSocket.connect((SERVER, dataPort))

# Send file to the server
with open("file.txt", "rb") as file:
    dataSocket.send(file.read())

<<<<<<< HEAD
=======

>>>>>>> 9df2cc6 (pull)
# Close the data socket
dataSocket.close()

# Send the command to the server
clientSocket.send("QUIT\r\n".encode())

# Receive the response from the server
response = clientSocket.recv(1024).decode()
print(response)

# Close the client socket
clientSocket.close()
