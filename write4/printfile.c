#include <stdio.h>

void printFileContent(const char *filename) {
    FILE *file = fopen(filename, "r");

    char buf;

    char line[256]; // Assuming each line has at most 255 characters

    while (fgets(line, sizeof(line), file)) {
        printf("%s", line); // Print each line
    }

    fclose(file);
}

int main(){
    char *filename = "flag.txt";
    printFileContent(filename);

    return 0;

}