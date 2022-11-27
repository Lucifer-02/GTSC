#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// check in csv file exists given 2 strings
int check(char *username, char *password) {
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

int main(void) {
  printf("checked: %d\n", check("minh@localserver.com", "1"));
}
