/*
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

 #include "atm.h"
 #include <stdio.h>
 #include <stdlib.h>
 
 static const char prompt[] = "ATM: ";
 
 int main(int argc, char *argv[])
 {
	 if (argc != 2)
	 {
		 fprintf(stderr, "Error opening ATM initialization file\n");
		 return 64;
	 }
 
	 const char *atm_file_path = argv[1];
	 ATM *atm = atm_create(atm_file_path);
	 if (!atm)
	 {
		 fprintf(stderr, "Error opening ATM initialization file\n");
		 return 64;
	 }
 
	 char user_input[1000];
 
	 printf("%s", prompt);
	 fflush(stdout);
 
	 // Limit fgets to the size of the buffer
	 while (fgets(user_input, sizeof(user_input), stdin) != NULL)
	 {
		 atm_process_command(atm, user_input);
		 if (atm->session_active)
		 {
			 printf("ATM (%s): ", atm->session_user);
		 }
		 else
		 {
			 printf("%s", prompt);
		 }
		 fflush(stdout);
	 }
	 return EXIT_SUCCESS;
 }
