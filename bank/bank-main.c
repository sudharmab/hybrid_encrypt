/* 
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

 #include <string.h>
 #include <sys/select.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "bank.h"
 #include "ports.h"
 
 static const char prompt[] = "BANK: ";
 
 int main(int argc, char**argv)
 {
 
    if (argc != 2) {
         fprintf(stderr, "Error opening bank initialization file\n");
         return 64;
     }
 
     const char* bank_file_path = argv[1];
     Bank* bank = bank_create(bank_file_path);
     if (!bank) {
         fprintf(stderr, "Error opening bank initialization file\n");
         return 64;
     }
 
    int n;
    char sendline[1000];
    char recvline[1000];
 
    printf("%s", prompt);
    fflush(stdout);
 
    while(1)
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        FD_SET(bank->sockfd, &fds);
        // Add error handling for select
        if (select(bank->sockfd + 1, &fds, NULL, NULL, NULL) < 0) {
         perror("select failed");
         return EXIT_FAILURE;
         }
 
        if(FD_ISSET(0, &fds))
        {
            fgets(sendline, sizeof(sendline),stdin);
            bank_process_local_command(bank, sendline, strlen(sendline));
            printf("%s", prompt);
            fflush(stdout);
        }
        else if(FD_ISSET(bank->sockfd, &fds))
        {
            n = bank_recv(bank, recvline, sizeof(recvline));
            bank_process_remote_command(bank, recvline, n);
        }
    }
    return EXIT_SUCCESS;
 }
