#include <winsock2.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

const int MAX_MSG_SIZE = 2048;

int const nServerPort = 21;

BOOL InitWinSock2_0();
uint16_t calculate_data_port(char *const msg);
void send_file(SOCKET socket, char *file_name);

int main(int argc, char *argv[]) {
  if (argc != 5) {
    printf("Usage: ./ftp_client_test.exe [ip] [username] [password] [file "
           "name]\n");
    return 0;
  }
  char *szServerIPAddr = argv[1];
  char *user = argv[2];
  char *password = argv[3];
  char *file_name = argv[4];

  //------------------ Initialize WinSock2.0 ----------------------------------
  if (!InitWinSock2_0()) {
    printf("Unable to Initialize Windows Socket environment, ERRORCODE = %d\n",
           WSAGetLastError());
    return -11;
  }

  SOCKET hClientSocket;
  hClientSocket = socket(AF_INET, SOCK_STREAM, 0);

  if (hClientSocket == INVALID_SOCKET) {
    printf("Unable to create Server socket\n");
    // Cleanup the environment initialized by WSAStartup()
    WSACleanup();
    return -12;
  }

  // Create the structure describing various Server parameters
  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET; // The address family. MUST be AF_INET
  serverAddr.sin_addr.s_addr = inet_addr(szServerIPAddr);
  serverAddr.sin_port = htons(nServerPort);

  // Connect to the server
  if (connect(hClientSocket, (struct sockaddr *)&serverAddr,
              sizeof(serverAddr)) < 0) {
    printf("Unable to connect to %s on port %d\n", szServerIPAddr, nServerPort);
    closesocket(hClientSocket);
    WSACleanup();
    return -13;
  }
  // -------------------------------------------------------------
  printf("Server connection established ............\n");

  char recvbuf[MAX_MSG_SIZE];
  // receive welcome message
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "220") == NULL) {
    return 220;
  }

  //------------------ username ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char username_msg[256];
  sprintf(username_msg, "USER %s\r\n", user);

  send(hClientSocket, username_msg, strlen(username_msg), 0);
  printf("Sent: %s", username_msg);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);

  //------------------ password ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char password_msg[256];
  sprintf(password_msg, "PASS %s\r\n", password);

  send(hClientSocket, password_msg, strlen(password_msg), 0);
  printf("Sent: %s", password_msg);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);

  //------------------ SET TYPE ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char const type[] = "TYPE A\r\n";
  send(hClientSocket, type, strlen(type), 0);
  printf("Sent: %s", type);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);

  //------------------ SET MODE ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char const mode[] = "PASV\r\n";
  send(hClientSocket, mode, strlen(mode), 0);
  printf("Sent: %s", mode);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  uint16_t dataPort = calculate_data_port(recvbuf);
  printf("Data port is: %d\n", dataPort);

  //------------------ SEND FILE COMMAND ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char cmd[256];
  sprintf(cmd, "STOR %s\r\n", file_name);
  send(hClientSocket, cmd, strlen(cmd), 0);
  printf("Sent: %s", cmd);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);

  //------------------ CREATE DATA CONNECTION ----------------
  SOCKET dataSocket;
  dataSocket = socket(AF_INET, SOCK_STREAM, 0);

  if (dataSocket == INVALID_SOCKET) {
    printf("Unable to create Server socket\n");
    // Cleanup the environment initialized by WSAStartup()
    WSACleanup();
    return -12;
  }

  // Create the structure describing various Server parameters
  struct sockaddr_in dataAddr;
  dataAddr.sin_family = AF_INET; // The address family. MUST be AF_INET
  dataAddr.sin_addr.s_addr = inet_addr(szServerIPAddr);
  dataAddr.sin_port = htons(dataPort);

  if (connect(dataSocket, (struct sockaddr *)&dataAddr, sizeof(dataAddr)) < 0) {
    printf("Unable to connect to %s on port %d\n", szServerIPAddr, dataPort);
    closesocket(dataSocket);
    WSACleanup();
    return -13;
  }
  printf("Data connection established ............\n");
  send_file(dataSocket, file_name);
  // close data connection
  // NOTE: You have to close the connection for the server to detect that the
  // file has been sent
  closesocket(dataSocket);

  //------------------ QUIT ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char *quit = "QUIT\r\n";
  send(hClientSocket, quit, strlen(quit), 0);
  printf("Sent: %s", quit);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);

  int iResult;
  // shutdown the connection since no more data will be sent
  iResult = shutdown(hClientSocket, SD_SEND);
  if (iResult == SOCKET_ERROR) {
    printf("shutdown failed with error: %d\n", WSAGetLastError());
    closesocket(hClientSocket);
    WSACleanup();
    return 1;
  }
}

BOOL InitWinSock2_0() {
  WSADATA wsaData;
  WORD wVersion = MAKEWORD(2, 0);
  if (!WSAStartup(wVersion, &wsaData))
    return TRUE;
  return FALSE;
}

uint16_t calculate_data_port(char *const msg) {
  uint16_t p1, p2;

  // walkthrough unuse token
  strtok(msg, ",");
  for (int i = 0; i < 3; i++) {
    strtok(NULL, ",");
  }

  // get need tokens
  p1 = atoi(strtok(NULL, ","));
  p2 = atoi(strtok(NULL, ")"));

  return p1 * 256 + p2;
}

void send_file(SOCKET socket, char *file_name) {
  int const CHUNK_SIZE = 256;
  FILE *fp;
  char buffer[CHUNK_SIZE];
  long filelen;

  // Opening file in reading mode
  fp = fopen(file_name, "rb");

  if (NULL == fp) {
    printf("file can't be opened \n");
    return;
  }

  fseek(fp, 0, SEEK_END); // Jump to the end of the file
  filelen = ftell(fp);    // Get the current byte offset in the file
  rewind(fp);             // Jump back to the beginning of the file

  for (long i = 0; i < filelen; i += CHUNK_SIZE) {
    fread(buffer, CHUNK_SIZE, 1, fp);
    send(socket, buffer, CHUNK_SIZE, 0);
  }

  // Closing the file
  fclose(fp);
}
