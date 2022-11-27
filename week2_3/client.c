#include <winsock2.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <ws2tcpip.h>

static char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};
const int MAX_MSG_SIZE = 2048;

char szServerIPAddr[32] =
    "192.168.12.108"; // Put here the IP address of the server
int nServerPort = 587;

struct MailMessage {
  char from[256];
  char password[256];
  char to[256];
  char subject[256];
  char body[2048];
};

char *base64_encode(const unsigned char *data, size_t input_length);
struct MailMessage createMail();

BOOL InitWinSock2_0();

int main() {

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
  printf("Connection established ............\n");

  struct MailMessage mail = createMail();
  char recvbuf[MAX_MSG_SIZE];
  // receive welcome message
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "220") == NULL) {
    return 220;
  }

  //----------- send EHLO -------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char *ehlo = "EHLO localhost\r\n";
  send(hClientSocket, ehlo, strlen(ehlo), 0);
  printf("Sent: %s", ehlo);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "250") == NULL) {
    return 250;
  }

  //------------------ login ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char *login = "AUTH LOGIN\r\n\0";
  send(hClientSocket, login, strlen(login), 0);
  printf("Sent: %s", login);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "334") == NULL) {
    return 334;
  }

  //------------------ username ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char *username_encoded = malloc(256);
  sprintf(username_encoded, "%s\r\n",
          base64_encode(mail.from, strlen(mail.from)));

  send(hClientSocket, username_encoded, strlen(username_encoded), 0);
  printf("Sent: %s", username_encoded);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "334") == NULL) {
    return 334;
  }

  //------------------ password ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char *password_encoded = malloc(256);
  sprintf(password_encoded, "%s\r\n",
          base64_encode(mail.password, strlen(mail.password)));

  send(hClientSocket, password_encoded, strlen(password_encoded), 0);
  printf("Sent: %s", password_encoded);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "235") == NULL) {
    return 235;
  }

  //------------------ MAIL FROM ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char *mailfrom = malloc(256);
  sprintf(mailfrom, "MAIL FROM:<%s>\r\n", mail.from);

  send(hClientSocket, mailfrom, strlen(mailfrom), 0);
  printf("Sent: %s", mailfrom);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "250") == NULL) {
    return 250;
  }

  //------------------ RCPT TO ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char *rcptto = malloc(256);
  sprintf(rcptto, "RCPT TO:<%s>\r\n", mail.to);

  send(hClientSocket, rcptto, strlen(rcptto), 0);
  printf("Sent: %s", rcptto);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "250") == NULL) {
    return 250;
  }

  //------------------ DATA ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char *cmd = "DATA\r\n";
  send(hClientSocket, cmd, strlen(cmd), 0);
  printf("Sent: %s", cmd);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "354") == NULL) {
    return 354;
  }

  //------------------ send DATA ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char *content = malloc(2048);
  sprintf(content,
          "From: %s\r\nTo: %s\r\nSubject: "
          "%s\r\n\r\n%s\r\n.\r\n",
          mail.from, mail.to, mail.subject, mail.body);
  send(hClientSocket, content, strlen(content), 0);
  printf("Sent: %s", content);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "250") == NULL) {
    return 250;
  }

  //------------------ QUIT ---------------------
  memset(recvbuf, 0, MAX_MSG_SIZE);
  char *quit = "QUIT\r\n";
  send(hClientSocket, quit, strlen(quit), 0);
  printf("Sent: %s", quit);
  recv(hClientSocket, recvbuf, MAX_MSG_SIZE, 0);
  printf("Received: %s", recvbuf);
  if (strstr(recvbuf, "221") == NULL) {
    return 221;
  }

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

char *base64_encode(const unsigned char *data, size_t input_length) {

  size_t output_length = 4 * ((input_length + 2) / 3);

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

struct MailMessage createMail() {
  struct MailMessage mail;

  printf("From: ");
  scanf("%s", mail.from);

  printf("To: ");
  scanf("%s", mail.to);

  printf("Password: ");
  scanf("%s", mail.password);

  printf("Subject: ");
  scanf("%s", mail.subject);

  printf("Body: ");
  scanf("%s", mail.body);

  return mail;
}

BOOL InitWinSock2_0() {
  WSADATA wsaData;
  WORD wVersion = MAKEWORD(2, 0);
  if (!WSAStartup(wVersion, &wsaData))
    return TRUE;
  return FALSE;
}
