// server.c
#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct client {
  int index;
  int sockID;
  struct sockaddr_in clientAddr;
  int len;
};

struct client Client[1024];
pthread_t thread[1024];
int clientCount = 0;
int thread_select = -1; // to select 1 thread at a time

void check_connections(char *output) {
  int check, error = 0, retval;
  int list_online_len = 0;
  int down_client_count = 0;
  int flag = 0;

  // check status connection
  for (int i = 0; i < clientCount; i++) {
    if (Client[i].sockID != -1) {
      check = send(Client[i].sockID, "1", 1024, 0);

      error = 0;
      socklen_t len = sizeof(error);
      retval = getsockopt(Client[i].sockID, SOL_SOCKET, SO_ERROR, &error, &len);

      if (error != 0 || retval != 0 || check == -1) {
        // update status socket
        Client[i].sockID = -1;
        flag = 1;

        // update select thread when selected client down
        if (i == thread_select) {
          for (int j = 0; j < clientCount; j++) {
            if (Client[j].sockID != -1) {
              thread_select = j;
              break;
            }
          }
        }
      } else {
        list_online_len +=
            snprintf(output + list_online_len, 1024,
                     "Client %d is at socket %d.\n", i + 1, Client[i].sockID);
      }
    }
  }

  // print number of online clients when change occurs
  if (list_online_len > 0 && flag == 1) {
    printf("-----------------------------\n");
    printf("Clients online:\n%s", output);
  };
}

void *doNetworking(void *ClientDetail) {

  char init_msg[1024];
  struct client *clientDetail = (struct client *)ClientDetail;
  int index = clientDetail->index;
  int clientSocket = clientDetail->sockID;

  printf("Client %d connected at socket %d.\n", index + 1, clientSocket);
  sprintf(init_msg, "[NOTE] YOUR CLIENT ID: %d\n", index + 1);
  send(clientSocket, init_msg, 1024, 0);

  // ignore SIGPIPE
  signal(SIGPIPE, SIG_IGN);

  while (1) {
    char data[1024];
    char msg[1024];
    char output[1024];
    int read = recv(clientSocket, data, 1024, 0);
    data[read] = '\0';

    if (index == thread_select) {
      check_connections(output);
    }

    // send list of online clients to client
    if (strcmp(data, "LIST") == 0) {
      check_connections(output);
      send(clientSocket, output, 1024, 0);
      continue;
    }

    // send message to client
    if (strcmp(data, "SEND") == 0) {

      // get client index
      read = recv(clientSocket, data, 1024, 0);
      data[read] = '\0';

      // convert string to int id
      int id = atoi(data) - 1;

      // get client message
      read = recv(clientSocket, data, 1024, 0);
      data[read] = '\0';

      sprintf(msg, "Client %d: ", index + 1);
      strcat(msg, data);

      // check client exist
      if (Client[id].sockID <= 0) {
        send(clientSocket, "[ERROR]Client not found.", 1024, 0);
      } else {
        send(Client[id].sockID, msg, 1024, 0);
        send(clientSocket, "[SUCCESS]", 1024, 0);
      }
      continue;
    }
  }

  return NULL;
}

int main() {

  // Creating socket file descriptor
  int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket < 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in serverAddr;

  // assign IP, PORT
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(8080);
  serverAddr.sin_addr.s_addr = htons(INADDR_ANY); //

  // Binding newly created socket to given IP and verification
  if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) ==
      -1) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  // Now server is ready to listen and verification
  if (listen(serverSocket, 1024) == -1) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  printf("Server started listenting on port 8080 ...........\n");

  while (1) {
    // Accept the data packet from client and verification
    Client[clientCount].sockID =
        accept(serverSocket, (struct sockaddr *)&Client[clientCount].clientAddr,
               (unsigned int *)&Client[clientCount].len);
    Client[clientCount].index = clientCount;

    // Function for chatting between clients and server
    pthread_create(&thread[clientCount], NULL, doNetworking,
                   (void *)&Client[clientCount]);

    // select thread for checking connection
    if (thread_select == -1) {
      thread_select = clientCount;
    }
    clientCount++;
  }

  // wait for all threads to finish
  for (int i = 0; i < clientCount; i++) {
    pthread_join(thread[i], NULL);
  }
}
