// list all file given by path

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int count = 1;
const int DEPTH = 4;
const int IS_FILE = 8;
const int IS_DIR = 4;

// return number of running process by name
int proc_find(const char *name) {
  DIR *dir;
  struct dirent *ent;
  char *endptr;
  char buf[512];
  int pid_count = 0;

  if (!(dir = opendir("/proc"))) {
    perror("can't open /proc");
    return -1;
  }

  while ((ent = readdir(dir)) != NULL) {
    /* if endptr is not a null character, the directory is not
     * entirely numeric, so ignore it */
    long lpid = strtol(ent->d_name, &endptr, 10);
    if (*endptr != '\0') {
      continue;
    }

    /* try to open the cmdline file */
    snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", lpid);
    FILE *fp = fopen(buf, "r");

    if (fp) {
      // get the first token in file and compare with name
      if (fgets(buf, sizeof(buf), fp) != NULL) {
		char *first = strtok(buf, " ");
		
		if (first != NULL && strcmp(name, first) == 0) {
          pid_count++;
		}
      }
    }
    fclose(fp);
  }

  return pid_count;
}

void scan(char *path, FILE *output) {
  DIR *dir;
  struct dirent *entry;
  char *fullpath;

  // check error path
  if ((dir = opendir(path)) == NULL) {
    fprintf(stderr, "opendir error: %s\n", path);
    return;
  }

  while ((entry = readdir(dir)) != NULL) {
    fullpath = (char *)malloc(strlen(path) + strlen(entry->d_name) + 2);
    sprintf(fullpath, "%s/%s", path, entry->d_name);

    if (entry->d_type == IS_DIR) {
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

    if (entry->d_type == IS_FILE) {
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

  // check running process
  int check = proc_find("./scan");
  if (check > 1) {
    printf("Error: process is already running!!!\n");
    exit(EXIT_FAILURE);
  }

  char input[] = "input.txt";
  char output[] = "output.txt";

  FILE *fin, *fout;
  char *line = NULL;
  size_t len = 0;

  // open a file to write
  fout = fopen(output, "w");
  if (fout == NULL) {
    fprintf(stderr, "fopen error: %s\n", output);
    exit(EXIT_FAILURE);
  }

  // open a file to read
  fin = fopen(input, "r");
  if (fin == NULL) {
    fprintf(stderr, "fopen error: %s", input);
    exit(EXIT_FAILURE);
  }

  // read input file line by line
  while (getline(&line, &len, fin) != -1) {
    // remove '\n' char at the end of line
    line[strlen(line) - 1] = '\0';
    scan(line, fout);
  }

  fclose(fin);
  fclose(fout);
  return 0;
}
