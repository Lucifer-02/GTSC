// list all file given by path

#include <windows.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tlhelp32.h>
#include <unistd.h>

int count = 1;
const int DEPTH = 10;

// count all process by name
int findMyProc(const char *procname) {

  HANDLE hSnapshot;
  PROCESSENTRY32 pe;
  BOOL hResult;
  int count = 0;

  // snapshot of all processes in the system
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot)
    return 0;

  // initializing size: needed for using Process32First
  pe.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  hResult = Process32First(hSnapshot, &pe);

  // retrieve information about the processes
  // and exit if unsuccessful
  while (hResult) {
    // if we find the process: return process ID
    if (strcmp(procname, pe.szExeFile) == 0) {
      count++;
    }
    hResult = Process32Next(hSnapshot, &pe);
  }

  // closes an open handle (CreateToolhelp32Snapshot)
  CloseHandle(hSnapshot);
  return count;
}

void scan(char *path, FILE *output) {
  DIR *dir;
  struct dirent *entry;
  char *fullpath;
  struct stat statbuf;

  // check error path
  if ((dir = opendir(path)) == NULL) {
    fprintf(stderr, "opendir error: %s\n", path);
    return;
  }

  while ((entry = readdir(dir)) != NULL) {
    fullpath = (char *)malloc(strlen(path) + strlen(entry->d_name) + 2);
    sprintf(fullpath, "%s\\%s", path, entry->d_name);

    // check error path
    if (stat(fullpath, &statbuf) == -1) {
      fprintf(stderr, "stat error: %s", fullpath);
      return;
    }

    // check if is a directory
    if (S_ISDIR(statbuf.st_mode)) {
      if (strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0) {
        continue;
      }

      count++;
      if (count >= DEPTH) {
        count = 0;
        break;
      }

      scan(fullpath, output);
    }

    if (S_ISREG(statbuf.st_mode)) {
      printf("%s\n", fullpath);

      // write to file
      fprintf(output, "%s\n", fullpath);
      count = 0;
    }
    free(fullpath);
  }

  closedir(dir);
}

int main() {

  // pause to test
  getchar();

  if (findMyProc("scan.exe") > 1) {
    printf("Error: process is already running!!!\n");
    exit(1);
  }

  char input[] = "input.txt";
  char output[] = "output.txt";
  char line[1024];

  // to write to output.txt file
  FILE *output_file = fopen(output, "w");
  if (output_file == NULL) {
    fprintf(stderr, "Can't open output file %s!", output);
    exit(1);
  }

  // to read input.txt line by line
  FILE *input_file = fopen(input, "r");
  if (input_file == NULL) {
	fprintf(stderr, "fopen error: %s\n", input);
	exit(1);
  }

  // to read input.txt line by line
  while (fgets(line, sizeof(line), input_file)) {
	// remove newline
	line[strlen(line) - 1] = '\0';
	scan(line, output_file);
  }

  fclose(input_file);
  fclose(output_file);

  return 0;
}
