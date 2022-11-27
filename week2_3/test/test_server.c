#include <winsock2.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_CLIENT 8

struct CLIENT_INFO {
  int index; // Index of client, used as parameter when sending to another
             // client
  int id;    // Id of client, used to identify client
  SOCKET hClientSocket;
  struct sockaddr_in clientAddr;
};

struct CLIENT_INFO client[MAX_CLIENT];

struct MailPackage {
  char from[256];
  char password[256];
  char to[256];
  char content[2048];
};
// Put here the IP address of the server
char szServerIPAddr[] = "192.168.22.8";

// The server port that will be used by clients to talk with the server
int nServerPort = 587;

// The number of clients that is always up-to-date
int clientCount = 0;

static char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};
static char *decoding_table = NULL;
const int MAX_MSG_SIZE = 2048;

char *base64_encode(const unsigned char *data, int input_length);
unsigned char *base64_decode(const char *data, int input_length);
BOOL InitWinSock2_0();
BOOL WINAPI ClientThread(LPVOID client);
char *get_mail_address(char const *str, int len);
bool check_login(char *username, char *password);

int main() {
  // Initialize Window Sockets
  if (!InitWinSock2_0()) {
    printf("Unable to Initialize Windows Socket environment%d\n",
           WSAGetLastError());
    return -1;
  }

  SOCKET hServerSocket;
  // Create server socket
  hServerSocket =
      socket(AF_INET,     // The address family. AF_INET specifies TCP/IP
             SOCK_STREAM, // Protocol type. SOCK_STREAM specified TCP
             0 // Protocol Name. Should be 0 for AF_INET address family
      );

  if (hServerSocket == INVALID_SOCKET) {
    printf("socket failed with error: %d\n", WSAGetLastError());
    WSACleanup();
    return 1;
  }

  // Create the structure describing various Server parameters
  struct sockaddr_in serverAddr;
  // The address family. MUST be AF_INET
  serverAddr.sin_family = AF_INET;
  // The IP address
  serverAddr.sin_addr.s_addr = inet_addr(szServerIPAddr);
  // The server's port
  serverAddr.sin_port = htons(nServerPort);

  // Bind the Server socket to the address & port
  if (bind(hServerSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) ==
      SOCKET_ERROR) {
    printf("Unable to bind to %s port %d\n", szServerIPAddr, nServerPort);
    // Free the socket and cleanup the environment initialized by WSAStartup()
    closesocket(hServerSocket);
    WSACleanup();
    return -2;
  }

  // Put the Server socket in listen state so that it can wait for client
  // connections
  if (listen(hServerSocket, SOMAXCONN) == SOCKET_ERROR) {
    printf("Unable to put server in listen state\n");
    // Free the socket and cleanup the environment initialized by WSAStartup()
    closesocket(hServerSocket);
    WSACleanup();
    return -3;
  }

  printf("Server started listening on port %d ............\n", nServerPort);

  //  Start the infinite loop
  while (clientCount < 10) { // Limit to 30 clients
    // For accept()'s parameter that needs a pointer
    int nSize = sizeof(client[clientCount].clientAddr);

    // As the socket is in listen mode there is a connection request pending.
    // Calling accept() will succeed and return the socket for the request.
    client[clientCount].hClientSocket =
        accept(hServerSocket,
               (struct sockaddr *)&client[clientCount].clientAddr, &nSize);

    // Check if a client is connected or not
    if (client[clientCount].hClientSocket == INVALID_SOCKET) {
      printf("ERROR: accept() function failed\n");
    } else {
      HANDLE hClientThread; // Variable that create/store a thread
      DWORD dwThreadId;     // Just for CreateThread()'s parameter

      // Store some info about the newly connected client
      client[clientCount].index = clientCount;
      client[clientCount].id = client[clientCount].hClientSocket;

      // Start the client thread
      hClientThread =
          CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ClientThread,
                       (LPVOID)&client[clientCount], 0, &dwThreadId);

      // Error
      if (hClientThread == NULL) {
        printf("Unable to create client thread\n");
      } else {
        CloseHandle(hClientThread);
      }
      // Add to total clients
      clientCount += 1;
    }
  }
  // Server shutting down
  closesocket(hServerSocket);
  WSACleanup();
  return 0;
}

BOOL InitWinSock2_0() {
  WSADATA wsaData;
  WORD wVersion = MAKEWORD(2, 0);
  if (!WSAStartup(wVersion, &wsaData))
    return TRUE;
  return FALSE;
}

BOOL WINAPI ClientThread(LPVOID client) {
  struct CLIENT_INFO *clientDetail = (struct CLIENT_INFO *)client;
  int index = clientDetail->index;
  int clientSocket = (int)clientDetail->hClientSocket;
  printf("#############################################\n");
  printf("Client %d connected.\n", index + 1);

  // Request from server: List all active clients
  char receiving[2048];
  char sending[256];
  struct MailPackage mail;

  strcpy(sending, "220 localhost ESMTP\r\n");
  send(clientSocket, sending, strlen(sending), 0);
  printf("Sent: %s", sending);
  recv(clientSocket, receiving, 2048, 0);
  printf("Received: %s", receiving);
  memset(sending, 0, 256);
  memset(receiving, 0, 2048);

  strcpy(
      sending,
      "250-localhost\r\n250-SIZE 20480000\r\n250-AUTH LOGIN\r\n250 HELP\r\n");
  send(clientSocket, sending, strlen(sending), 0);
  printf("Sent: %s", sending);
  recv(clientSocket, receiving, 2048, 0);
  printf("Received: %s", receiving);
  memset(sending, 0, 256);
  memset(receiving, 0, 2048);

  const char *username = "Username:";
  sprintf(sending, "334 %s\r\n", base64_encode(username, strlen(username)));
  send(clientSocket, sending, strlen(sending), 0);
  printf("Sent: %s", sending);
  recv(clientSocket, receiving, 2048, 0);
  printf("Received: %s", receiving);
  // save username to mail
  char *username_decoded = base64_decode(receiving, strlen(receiving) - 2);
  strcpy(mail.from, username_decoded);
  free(username_decoded);
  memset(sending, 0, 256);
  memset(receiving, 0, 2048);

  const char *password = "Password:";
  sprintf(sending, "334 %s\r\n", base64_encode(password, strlen(password)));
  send(clientSocket, sending, strlen(sending), 0);
  printf("Sent: %s", sending);
  recv(clientSocket, receiving, 2048, 0);
  printf("Received: %s", receiving);
  // save password to mail
  char *password_decoded = base64_decode(receiving, strlen(receiving) - 2);
  strcpy(mail.password, password_decoded);
  free(password_decoded);
  memset(sending, 0, 256);
  memset(receiving, 0, 2048);

  if (check_login(mail.from, mail.password)) {
    strcpy(sending, "235 authenticated.\r\n");
  } else {
    strcpy(sending, "535 authentication failed.\r\n");
    send(clientSocket, sending, strlen(sending), 0);
    printf("--------------- FAILED ---------------\n");
    goto end;
  }
  send(clientSocket, sending, strlen(sending), 0);
  printf("Sent: %s", sending);
  recv(clientSocket, receiving, 2048, 0);
  printf("Received: %s", receiving);
  memset(sending, 0, 256);
  memset(receiving, 0, 2048);

  strcpy(sending, "250 OK\r\n");
  send(clientSocket, sending, strlen(sending), 0);
  printf("Sent: %s", sending);
  recv(clientSocket, receiving, 2048, 0);
  printf("Received: %s", receiving);
  // save mail to
  char *mail_to = get_mail_address(receiving, strlen(receiving));
  strcpy(mail.to, mail_to);
  free(mail_to);
  memset(sending, 0, 256);
  memset(receiving, 0, 2048);

  strcpy(sending, "250 OK\r\n");
  send(clientSocket, sending, strlen(sending), 0);
  printf("Sent: %s", sending);
  recv(clientSocket, receiving, 2048, 0);
  printf("Received: %s", receiving);
  memset(sending, 0, 256);
  memset(receiving, 0, 2048);

  strcpy(sending, "354 OK, send.\r\n");
  send(clientSocket, sending, strlen(sending), 0);
  printf("Sent: %s", sending);
  recv(clientSocket, receiving, 2048, 0);
  // save mail content
  strcpy(mail.content, receiving);
  printf("--------------- CONTENT ---------------\n");
  printf("%s", receiving);
  printf("---------------   END   ---------------\n");
  memset(sending, 0, 256);
  memset(receiving, 0, 2048);

  strcpy(sending, "250 Queued\r\n");
  send(clientSocket, sending, strlen(sending), 0);
  printf("Sent: %s", sending);
  recv(clientSocket, receiving, 2048, 0);
  printf("Received: %s", receiving);
  memset(sending, 0, 256);
  memset(receiving, 0, 2048);

  strcpy(sending, "221 goodbye\r\n");
  send(clientSocket, sending, strlen(sending), 0);
  printf("Sent: %s", sending);
  memset(sending, 0, 256);
  memset(receiving, 0, 2048);

  printf("--------------- SUCCESS ---------------\n");

end:
  // close thread and socket
  closesocket(clientSocket);
  printf("Client %d disconnected.\n", index + 1);
  return TRUE;
}

char *base64_encode(const unsigned char *data, int input_length) {

  int output_length = 4 * ((input_length + 2) / 3);

  char *encoded_data = malloc(output_length + 1);
  if (encoded_data == NULL)
    return NULL;

  for (int i = 0, j = 0; i < input_length;) {

    uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
    uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
    uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

    encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
  }

  for (int i = 0; i < mod_table[input_length % 3]; i++) {
    encoded_data[output_length - 1 - i] = '=';
  }

  encoded_data[output_length] = '\0';

  return encoded_data;
}

void build_decoding_table() {

  decoding_table = malloc(256);

  for (int i = 0; i < 64; i++)
    decoding_table[(unsigned char)encoding_table[i]] = i;
}

void base64_cleanup() { free(decoding_table); }
unsigned char *base64_decode(const char *data, int input_length) {

  if (decoding_table == NULL)
    build_decoding_table();

  if (input_length % 4 != 0)
    return NULL;

  int output_length = input_length / 4 * 3;
  if (data[input_length - 1] == '=')
    (output_length)--;
  if (data[input_length - 2] == '=')
    (output_length)--;

  unsigned char *decoded_data = malloc(output_length);
  if (decoded_data == NULL)
    return NULL;

  for (int i = 0, j = 0; i < input_length;) {

    uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
    uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
    uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
    uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

    uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) +
                      (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

    if (j < output_length)
      decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
    if (j < output_length)
      decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
    if (j < output_length)
      decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
  }

  decoded_data[output_length] = '\0';
  return decoded_data;
}
char *get_mail_address(char const *str, int len) {
  char *result = malloc(40);
  int begin = 0;
  for (int i = 0; i < len; i++) {
    if (str[i] == '<') {
      begin = i + 1;
      break;
    }
  }
  for (int j = 0; j < len - begin; j += 1) {
    result[j] = str[j + begin];
  }

  // remove '>','\r','\n' at the end
  result[len - begin - 3] = '\0';

  return result;
}

// check in accounts file if the account exists
bool check_login(char *username, char *password) {
  FILE *fp;
  char *acc;
  char *pass;
  int found = 0;

  fp = fopen("accounts.txt", "r");
  if (fp == NULL)
    exit(EXIT_FAILURE);

  char line[100];
  while (fgets(line, sizeof(line), fp)) {
    // remove new line character
    line[strlen(line) - 1] = '\0';
    acc = strtok(line, ";");
    pass = strtok(NULL, ";");
    if (strcmp(acc, username) == 0 && strcmp(pass, password) == 0) {
      found = 1;
      break;
    }
  }

  fclose(fp);
  return found;
}
