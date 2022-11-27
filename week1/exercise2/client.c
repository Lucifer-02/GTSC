// client.c
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// receive messages
void *doRecieving(void *sockID) {

  int clientSocket = *((int *)sockID);

  while (1) {

    char data[1024];
    int read = recv(clientSocket, data, 1024, 0);
    data[read] = '\0';
	
	// ignore if received check connection message 
    if (data[0] == '1') {
      continue;
    } else {
      printf("%s\n", data);
    }
  }
}

int main() {

  struct sockaddr_in serverAddr;
  pthread_t thread;

  // socket create and verification
  int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (clientSocket == -1) {
    printf("socket creation failed...\n");
    exit(0);
  }

  // assign IP, PORT
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(8080);
  serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

  // connect the client socket to server socket
  if (connect(clientSocket, (struct sockaddr *)&serverAddr,
              sizeof(serverAddr)) == -1) {
    printf("connection with the server failed...\n");
    exit(0);
  }

  printf("Connection established ............\n");

  pthread_create(&thread, NULL, doRecieving, (void *)&clientSocket);

  while (1) {

    char input[1024];
    scanf("%s", input);

    if (strcmp(input, "LIST") == 0) {

      send(clientSocket, input, 1024, 0);
    }
    if (strcmp(input, "SEND") == 0) {

      send(clientSocket, input, 1024, 0);
      scanf("%s", input);
      send(clientSocket, input, 1024, 0);
      scanf("%[^\n]s", input);
      send(clientSocket, input, 1024, 0);
    }
  }
}
