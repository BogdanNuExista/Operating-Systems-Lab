#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <sys/wait.h>
#include <stdbool.h>

#define MAX_PATH_LENGTH 1024
#define MAX_METADATA_LENGTH 1024
#define MALICIOUS_DIR_NAME "MaliciousFiles"
#define READ_END 0
#define WRITE_END 1

void generate_metadata(const char *path, char *metadata) {

    struct stat *file_stat = malloc(sizeof(struct stat));

    if (lstat(path, file_stat) == -1) {
        perror("Failed to get file status");
        exit(EXIT_FAILURE);
    }
    
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    sprintf(metadata, "%s:\n Marca temporala=%d-%02d-%02d %02d:%02d:%02d\n Size=%ld bytes\n Permissions=%d\n Ultima modificare=%s Numar Inode=%ld\n\n",
            path,  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec ,file_stat->st_size, 
            file_stat->st_mode & 0777, ctime(&file_stat->st_ctime) ,file_stat->st_ino);

    free(file_stat); 
}

bool malicious_check_result; // Global variable to store the result of the malicious check

void execute_malicious_check_script(const char *file_path) {
    pid_t pid = fork(); // Create a new process

    if (pid < 0) {
        perror("Fork failed");
        malicious_check_result = false;
    } else if (pid == 0) {
        // Child process
        execl("./verify_for_malicious.sh", "./verify_for_malicious.sh", file_path, NULL);
        // If execl returns, it means it failed
        perror("execl failed");
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0); // Wait for the child process to finish
        // Check if the child process exited normally
        if (WIFEXITED(status)) {
            // Extract the exit status of the child process
            int exit_status = WEXITSTATUS(status);
            // Set global variable based on the exit status
            malicious_check_result = (exit_status == 0);
        } else {
            perror("Child process did not exit normally");
            malicious_check_result = false;
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void create_or_update_snapshot(const char *dir_path, const char *output_dir) {
    DIR *dir;
    struct dirent *entry;
    char snapshot_path[MAX_PATH_LENGTH];
    char entry_metadata[MAX_METADATA_LENGTH];

    // Open directory
    if ((dir = opendir(dir_path)) == NULL) {
        perror("Failed to open directory");
        exit(EXIT_FAILURE);
    }

    // Create snapshot file path in the output directory
    snprintf(snapshot_path, MAX_PATH_LENGTH, "%s/Snapshot.txt", output_dir);

    // Open or create snapshot file
    int snapshot_fd = open(snapshot_path, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);
    if (snapshot_fd == -1) {
        perror("Failed to open or create snapshot file");
        closedir(dir);
        exit(EXIT_FAILURE);
    }

    // Iterate through directory entries
    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".." directories
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char entry_path[MAX_PATH_LENGTH];
        snprintf(entry_path, MAX_PATH_LENGTH, "%s/%s", dir_path, entry->d_name);

        // Generate metadata for the entry
        generate_metadata(entry_path, entry_metadata);

        if(entry->d_type == DT_REG){
            if ((access(entry_path, R_OK) == -1) || (access(entry_path, W_OK)==-1)) {
                execute_malicious_check_script(entry_path);

                if(malicious_check_result==0)
                    continue; /// Do not do the snapshot for a malicious file
            }
        }

        // Write metadata to snapshot file only if it's not a directory
        if(entry->d_type != DT_DIR) {
            if (write(snapshot_fd, entry_metadata, strlen(entry_metadata)) == -1) {
                perror("Failed to write metadata to snapshot file");
                closedir(dir);
                close(snapshot_fd);
                exit(EXIT_FAILURE);
            }
        }
        
        // If entry is a directory, recursively call create_or_update_snapshot()
        if (entry->d_type == DT_DIR) {
            create_or_update_snapshot(entry_path, output_dir);
        }
    }

    // Close directory and snapshot file
    closedir(dir);
    close(snapshot_fd);

    printf("Snapshot for directory %s created or updated successfully.\n", dir_path);
}

int main(int argc, char *argv[]) {
    if (argc < 5 || argc > 14) {
        exit(EXIT_FAILURE);
    }

    const char *output_dir = argv[2];

    for (int i = 5; i < argc; i++) {
        
        pid_t pid=fork();
        if(pid==-1)
        {
            perror("Fork failed\n");
            exit(-1);
        }
        else if(pid==0)
        {
            create_or_update_snapshot(argv[i], output_dir);
            exit(EXIT_SUCCESS);
        }
       
    }

    int status;
    while(wait(&status)>0);

    return 0;
}