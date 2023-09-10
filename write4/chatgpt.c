#include <stdio.h>

void printFileContent(const char *filename) {
    FILE *file = fopen(filename, "r"); // Open the file in read mode

    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    char line[256]; // Assuming each line has at most 255 characters

    while (fgets(line, sizeof(line), file)) {
        printf("%s", line); // Print each line
    }

    fclose(file); // Close the file when done
}

int main() {
    const char *filename = "flag.txt";
    printFileContent(filename);
    
    return 0;
}
