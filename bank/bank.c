#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <regex.h>
#include <stdio.h>
Bank *bank_create(const char *bank_file_path)
{
	FILE *fp = fopen(bank_file_path, "r"); // opens reads the file
	if (!fp)
	{
		return NULL; // main() will print the error and exit
	}
	// Read full file into buffer
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char *buffer = malloc(fsize + 1);
	fread(buffer, 1, fsize, fp);
	buffer[fsize] = '\0';
	fclose(fp);
	Bank *bank = (Bank *)malloc(sizeof(Bank));
	if (bank == NULL)
	{
		perror("Could not allocate Bank");
		exit(1);
	}
	// Set up the network state
	bank->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	bzero(&bank->rtr_addr, sizeof(bank->rtr_addr));
	bank->rtr_addr.sin_family = AF_INET;
	bank->rtr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	bank->rtr_addr.sin_port = htons(ROUTER_PORT);
	bzero(&bank->bank_addr, sizeof(bank->bank_addr));
	bank->bank_addr.sin_family = AF_INET;
	bank->bank_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	bank->bank_addr.sin_port = htons(BANK_PORT);
	bind(bank->sockfd, (struct sockaddr *)&bank->bank_addr, sizeof(bank->bank_addr));
	// --- Parse RSA Private Key (Bank) ---
	BIO *priv_bio = BIO_new_mem_buf(buffer, -1);
	bank->private_key = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL); // Updated API
	BIO_free(priv_bio);
	if (!bank->private_key)
	{
		fprintf(stderr, "Failed to load Bank private key\n");
		free(buffer);
		free(bank);
		return NULL;
	}
	// --- Parse ATM Public Key ---
	char *atm_pub_start = strstr(buffer, "-----BEGIN PUBLIC KEY-----");
	if (!atm_pub_start)
	{
		fprintf(stderr, "ATM public key block not found\n");
		free(buffer);
		free(bank);
		return NULL;
	}
	BIO *pub_bio = BIO_new_mem_buf(atm_pub_start, -1);
	bank->atm_public_key = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL); // Updated API
	BIO_free(pub_bio);
	if (!bank->atm_public_key)
	{
		fprintf(stderr, "Failed to load ATM public key\n");
		free(buffer);
		free(bank);
		return NULL;
	}
	// --- Parse AES key ---
	char *aes_key_line = strstr(buffer, "AES_KEY=");
	if (!aes_key_line)
	{
		fprintf(stderr, "AES key line not found\n");
		free(buffer);
		free(bank);
		return NULL;
	}
	aes_key_line += strlen("AES_KEY=");
	char *newline = strchr(aes_key_line, '\n');
	if (newline)
		*newline = '\0';
	// Decode the base64-encoded AES key
	unsigned char aes_key_bin[32];
	int decoded_len = EVP_DecodeBlock(aes_key_bin, (const unsigned char *)aes_key_line, strlen(aes_key_line));
	// EVP_DecodeBlock may return extra padding; manually strip
	if (decoded_len <= 0)
	{
		fprintf(stderr, "AES key decode failed\n");
		free(buffer);
		free(bank);
		return NULL;
	}
	// If needed, trim padding bytes (= encoded as '\0')
	while (decoded_len > 0 && aes_key_bin[decoded_len - 1] == '\0')
	{
		decoded_len--;
	}
	// Now check it's exactly 32 bytes
	if (decoded_len != 32)
	{
		fprintf(stderr, "AES key wrong length: got %d, expected 32\n", decoded_len);
		free(buffer);
		free(bank);
		return NULL;
	}
	// Copy the decoded AES key into the bank's AES key field
	memcpy(bank->aes_key, aes_key_bin, 32);
	free(buffer);
	// FIX: initialize user_list to NULL
	bank->user_list = NULL;
	return bank;
}
void bank_free(Bank *bank)
{
	if (bank != NULL)
	{
		close(bank->sockfd);
		free(bank);
	}
}
ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
	// Returns the number of bytes sent; negative on error
	return sendto(bank->sockfd, data, data_len, 0,
				  (struct sockaddr *)&bank->rtr_addr, sizeof(bank->rtr_addr));
}
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
	// Returns the number of bytes received; negative on error
	return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}
int matches_regex(const char *string, const char *pattern)
{
	regex_t regex;
	int result;
	// Compile the regular expression
	result = regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB);
	if (result)
	{
		return 0; // Failed to compile regex
	}
	// Execute the regex
	result = regexec(&regex, string, 0, NULL, 0);
	regfree(&regex);	// Clean up
	return result == 0; // 0 means match
}
User *find_user(Bank *bank, const char *username)
{
	// printf("[DEBUG] Looking up user: '%s'\n", username);
	User *curr = bank->user_list;
	while (curr != NULL)
	{
		// printf("User_in_list: '%s'\n", curr->username);
		if (strcmp(curr->username, username) == 0)
		{
			return curr; // Found match
		}
		curr = curr->next;
	}
	return NULL; // Not found
}
int insert_user(Bank *bank, const char *username, const char *pin, int balance)
{
	// 1. Check if user already exists
	if (find_user(bank, username) != NULL)
	{
		return 0;
	}
	// 2. Allocate memory for new user
	User *new_user = malloc(sizeof(User));
	if (!new_user)
	{
		perror("malloc failed");
		return 0;
	}
	// 3. Fill in user fields safely
	strncpy(new_user->username, username, 250);
	new_user->username[250] = '\0'; // just in case
	strncpy(new_user->pin, pin, 4);
	new_user->pin[4] = '\0';
	new_user->balance = balance;
	// 4. Insert at the beginning of the linked list
	new_user->next = bank->user_list;
	bank->user_list = new_user;
	return 1;
}
void bank_process_local_command(Bank *bank, char *command, size_t len)
{
	// TODO: Implement the bank's local commands
	// so function: bank admin (typing into stdin)
	// needs to manage accounts, pins, and etc maybe use sql
	// each person added, and create new account ...
	//
	// remember
	// create-user <user-name> <pin> <balance> validate input and create in mem, create a <user>.cardfile
	// deposit <user-name> <amt > -> val input and upadte balance
	// balance <user-name> val input and print it
	// print err if anything else
	//
	//****decrpyt and call local with decrypted message btw****
	// Create user this will later call insert_user into our linkedlist
	// will most likely use strncmp over stcmp due to other arguments passed in for each of these
	// with possibly strtok and split based on spaces
	if (strncmp(command, "create-user ", 12) == 0)
	{
		printf("Processing create-user command: %s\n", command);
		char *cmd_copy = strdup(command);
		if (!cmd_copy)
		{
			fprintf(stderr, "Failed to allocate memory for command copy\n");
			return;
		}
		strtok(cmd_copy, " ");
		char *username = strtok(NULL, " ");
		char *pin = strtok(NULL, " ");
		char *balance = strtok(NULL, " ");
		if (!username || !pin || !balance || strtok(NULL, " "))
		{
			printf("Usage: create-user <user-name> <pin> <balances>\n");
			free(cmd_copy);
			return;
		}
		if (!matches_regex(username, "[a-zA-Z]+") ||
			!matches_regex(pin, "[0-9][0-9][0-9][0-9]") ||
			!matches_regex(balance, "[0-9]+"))
		{
			printf("Usage: create-user <user-name> <pin> <balances>\n");
			free(cmd_copy);
			return;
		}
		int bal = atoi(balance);
		if (!insert_user(bank, username, pin, bal))
		{
			printf("Error: user %s already exists\n", username);
			free(cmd_copy);
			return;
		}
		char filename[300];
		snprintf(filename, sizeof(filename), "%s.card", username);
		FILE *fp = fopen(filename, "w");
		if (!fp)
		{
			printf("Error creating card file for user %s\n", username);
			User *head = bank->user_list;
			bank->user_list = head->next;
			free(head);
			free(cmd_copy);
			return;
		}
		fprintf(fp, "%s\n", username);
		fclose(fp);
		printf("Created user %s\n", username);
		free(cmd_copy);
	}
	// deposit a certain amount
	else if (strncmp(command, "deposit ", 8) == 0)
	{
		char *cmd_copy = strdup(command); // duplicates command
		strtok(cmd_copy, " ");
		char *username = strtok(NULL, " ");
		char *amt_str = strtok(NULL, " ");
		if (!username || !amt_str || strtok(NULL, " "))
		{
			printf("Usage: deposit <user-name> <amt>\n");
			// printf("Usage:  deposit %s %s", username, amt_str);
			free(cmd_copy);
			return;
		}
		if (!matches_regex(username, "[a-zA-Z]+") || !matches_regex(amt_str, "[0-9]+"))
		{
			printf("Usage: deposit <user-name> <amt>\n");
			// printf("Usage:  deposit %s %s", username, amt_str);
			free(cmd_copy);
			return;
		}
		User *u = find_user(bank, username);
		if (!u)
		{
			printf("No such user\n");
			free(cmd_copy);
			return;
		}
		int amt = atoi(amt_str);
		// Check for integer overflow
		if ((amt > 0 && u->balance > INT_MAX - amt) || amt < 0)
		{
			printf("Too rich for this program\n");
			free(cmd_copy);
			return;
		}
		u->balance += amt;
		printf("$%d added to %s's account\n", amt, username);
		free(cmd_copy);
	}
	else if (strncmp(command, "balance ", 8) == 0)
	{
		char *cmd_copy = strdup(command); // duplicates command
		strtok(cmd_copy, " ");
		char *username = strtok(NULL, " ");
		if (!username || strtok(NULL, " "))
		{
			printf("Usage:  balance <user-name>\n");
			// printf("Usage:  balance %\ns", username);
			free(cmd_copy);
			return;
		}
		char clean_username[251];
		strncpy(clean_username, username, 250);
		clean_username[250] = '\0';
		clean_username[strcspn(clean_username, "\n")] = '\0';
		if (!matches_regex(clean_username, "[a-zA-Z]+"))
		{
			printf("Usage:  balance %s", clean_username);
			free(cmd_copy);
			return;
		}
		User *u = find_user(bank, clean_username);
		if (!u)
		{
			printf("No such user\n");
			free(cmd_copy);
			return;
		}
		printf("$%d\n", u->balance);
		free(cmd_copy);
	}
	else
	{
		printf("Invalid command\n");
	}
}
int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
					unsigned char *tag, unsigned char *key, unsigned char *iv,
					unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;
	// Create and initialize the context
	if (!(ctx = EVP_CIPHER_CTX_new()))
	{
		return -1;
	}
	// Initialize the decryption operation with AES-256-GCM
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	// Set the IV length
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	// Initialize the key and IV
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	// Provide the ciphertext for decryption
	if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	plaintext_len = len;
	// Set the expected tag value
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	// Finalize the decryption
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	EVP_CIPHER_CTX_free(ctx);
	if (ret > 0)
	{
		plaintext_len += len;
		return plaintext_len; // Success
	}
	else
	{
		return -1; // Decryption failed
	}
}
int verify_signature(EVP_PKEY *pubkey, unsigned char *msg, size_t msg_len, unsigned char *signature)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx)
	{
		fprintf(stderr, "Failed to create EVP_MD_CTX\n");
		return 0;
	}
	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey) <= 0)
	{
		fprintf(stderr, "Failed to initialize digest verification\n");
		EVP_MD_CTX_free(ctx);
		return 0;
	}
	if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) <= 0)
	{
		fprintf(stderr, "Failed to update digest verification\n");
		EVP_MD_CTX_free(ctx);
		return 0;
	}
	int verified = EVP_DigestVerifyFinal(ctx, signature, 256);
	EVP_MD_CTX_free(ctx);
	return verified == 1;
}

void send_secure_response(Bank *bank, const char *plaintext_response)
{
	unsigned char iv[16];
	unsigned char tag[16];
	unsigned char ciphertext[1000];
	unsigned char signature[256];

	int len1 = 0, len2 = 0; // Separate lengths
	int ciphertext_len = 0;

	// Generate a random IV
	if (!RAND_bytes(iv, sizeof(iv)))
	{
		fprintf(stderr, "RAND_bytes failed\n");
		return;
	}

	// AES-GCM Encrypt the response
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		fprintf(stderr, "EVP_CIPHER_CTX allocation failed\n");
		return;
	}

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ||
		!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) ||
		!EVP_EncryptInit_ex(ctx, NULL, NULL, bank->aes_key, iv))
	{
		fprintf(stderr, "AES-GCM init failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	if (!EVP_EncryptUpdate(ctx, ciphertext, &len1, (unsigned char *)plaintext_response, strlen(plaintext_response)))
	{
		fprintf(stderr, "AES-GCM update failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	if (!EVP_EncryptFinal_ex(ctx, ciphertext + len1, &len2))
	{
		fprintf(stderr, "AES-GCM final failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag))
	{
		fprintf(stderr, "AES-GCM get tag failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	ciphertext_len = len1 + len2;
	EVP_CIPHER_CTX_free(ctx);

	// Sign the ciphertext with the Bank's private key
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx)
	{
		fprintf(stderr, "Failed to allocate EVP_MD_CTX\n");
		return;
	}

	if (!EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, bank->private_key) ||
		!EVP_DigestSignUpdate(mdctx, ciphertext, ciphertext_len))
	{
		fprintf(stderr, "Failed to sign ciphertext\n");
		EVP_MD_CTX_free(mdctx);
		return;
	}

	size_t sig_len = 256;
	if (!EVP_DigestSignFinal(mdctx, signature, &sig_len) || sig_len != 256)
	{
		fprintf(stderr, "Signature length is not 256 as expected\n");
		EVP_MD_CTX_free(mdctx);
		return;
	}
	EVP_MD_CTX_free(mdctx);

	// Assemble the response packet
	size_t total_len = ciphertext_len + sig_len + sizeof(tag) + sizeof(iv);
	unsigned char *packet = malloc(total_len);
	if (!packet)
	{
		fprintf(stderr, "Failed to allocate memory for response packet\n");
		return;
	}

	size_t offset = 0;
	memcpy(packet + offset, ciphertext, ciphertext_len);
	offset += ciphertext_len;
	memcpy(packet + offset, signature, sig_len);
	offset += sig_len;
	memcpy(packet + offset, tag, sizeof(tag));
	offset += sizeof(tag);
	memcpy(packet + offset, iv, sizeof(iv));
	offset += sizeof(iv);

	// Debug print
	// printf("[BANK DEBUG] Sending secure response\n");
	// printf(" - Ciphertext length: %d\n", ciphertext_len);
	// printf(" - IV: ");
	// for (int i = 0; i < 16; i++)
	// 	printf("%02x", iv[i]);
	// printf("\n - Tag: ");
	// for (int i = 0; i < 16; i++)
	// 	printf("%02x", tag[i]);
	// printf("\n - Signature length: %zu\n", sig_len);

	// Send the encrypted response to the ATM
	bank_send(bank, (char *)packet, total_len);
	free(packet);
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
	if (len < 256 + 256 + 16 + 16)
	{
		printf("Invalid message length\n");
		return;
	}
	size_t offset = 0;
	unsigned char *c_key = (unsigned char *)(command + offset);
	offset += 256;
	size_t ciphertext_len = len - offset - 256 - 16 - 16;
	// printf("[DEBUG] Received encrypted AES key (hex): ");
	// for (int i = 0; i < 256; i++)
	// 	printf("%02x", c_key[i]);
	// printf("\n");
	// printf("[DEBUG] Attempting to decrypt AES key\n");
	unsigned char *ciphertext = (unsigned char *)(command + offset);
	offset += ciphertext_len;
	unsigned char *signature = (unsigned char *)(command + offset);
	offset += 256;
	unsigned char *tag = (unsigned char *)(command + offset);
	offset += 16;
	unsigned char *iv = (unsigned char *)(command + offset);
	offset += 16;
	// unsigned char aes_key[32];
	// size_t aes_key_len = sizeof(aes_key);

	// EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(bank->private_key, NULL);
	// if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 ||
	// 	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
	// 	EVP_PKEY_decrypt(ctx, aes_key, &aes_key_len, c_key, 256) <= 0)
	// {
	// 	int ret1 = EVP_PKEY_decrypt_init(ctx);
	// 	printf("[DEBUG] EVP_PKEY_decrypt_init returned: %d\n", ret1);

	// 	int ret2 = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
	// 	printf("[DEBUG] EVP_PKEY_CTX_set_rsa_padding returned: %d\n", ret2);

	// 	int ret3 = EVP_PKEY_decrypt(ctx, aes_key, &aes_key_len, c_key, 256);
	// 	printf("[DEBUG] EVP_PKEY_decrypt returned: %d (expected > 0)\n", ret3);

	// 	printf("AES key decryption failed\n");
	// 	if (ctx)
	// 		EVP_PKEY_CTX_free(ctx);
	// 	return;
	// }
	// EVP_PKEY_CTX_free(ctx);

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(bank->private_key, NULL);
	if (!ctx)
	{
		printf("Failed to create EVP_PKEY_CTX\n");
		return;
	}

	if (EVP_PKEY_decrypt_init(ctx) <= 0)
	{
		// printf("[DEBUG] EVP_PKEY_decrypt_init failed\n");
		EVP_PKEY_CTX_free(ctx);
		return;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
	{
		// printf("[DEBUG] EVP_PKEY_CTX_set_rsa_padding failed\n");
		EVP_PKEY_CTX_free(ctx);
		return;
	}

	if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
	{
		// printf("[DEBUG] EVP_PKEY_CTX_set_rsa_oaep_md failed\n");
		EVP_PKEY_CTX_free(ctx);
		return;
	}

	// Phase 1: determine buffer size
	size_t aes_key_len = 0;
	if (EVP_PKEY_decrypt(ctx, NULL, &aes_key_len, c_key, 256) <= 0)
	{
		// printf("[DEBUG] EVP_PKEY_decrypt (size query) failed\n");
		EVP_PKEY_CTX_free(ctx);
		return;
	}

	// Phase 2: actual decryption
	unsigned char decrypted_key[512]; // just in case key is large
	if (aes_key_len > sizeof(decrypted_key))
	{
		// printf("[DEBUG] Decrypted AES key too large\n");
		EVP_PKEY_CTX_free(ctx);
		return;
	}

	if (EVP_PKEY_decrypt(ctx, decrypted_key, &aes_key_len, c_key, 256) <= 0)
	{
		// printf("[DEBUG] EVP_PKEY_decrypt (actual decryption) failed\n");
		EVP_PKEY_CTX_free(ctx);
		return;
	}
	EVP_PKEY_CTX_free(ctx);

	// Take first 32 bytes of decrypted key as AES key
	if (aes_key_len < 32)
	{
		// printf("[DEBUG] Decrypted AES key too short: %zu\n", aes_key_len);
		return;
	}
	unsigned char aes_key[32];
	memcpy(aes_key, decrypted_key, 32);

	// EVP_PKEY_CTX_free(ctx);

	unsigned char plaintext[1024];
	int pt_len = aes_gcm_decrypt(ciphertext, ciphertext_len, tag, aes_key, iv, plaintext);
	if (pt_len < 0)
	{
		printf("AES-GCM decryption failed\n");
		return;
	}
	plaintext[pt_len] = '\0';
	if (!verify_signature(bank->atm_public_key, ciphertext, ciphertext_len, signature))
	{
		printf("Signature verification failed\n");
		return;
	}
	// printf("[BANK] Secure command received: %s\n", plaintext);

	// Parse the decrypted command
	char *cmd_copy = strdup((char *)plaintext);
	char *cmd = strtok(cmd_copy, " ");
	char *arg1 = strtok(NULL, " ");
	char *arg2 = strtok(NULL, " ");

	if (cmd && strcmp(cmd, "login") == 0 && arg1 && arg2 && !strtok(NULL, " "))
	{
		User *u = find_user(bank, arg1);
		if (u && strcmp(u->pin, arg2) == 0)
		{
			// Success: user exists and PIN matches
			bank_send(bank, "Authorized\n", strlen("Authorized\n"));
		}
		else
		{
			// Failure: user doesn't exist or PIN is wrong
			bank_send(bank, "Not authorized\n", strlen("Not authorized\n"));
		}
	}
	else if (cmd && strcmp(cmd, "withdraw") == 0 && arg1)
	{
		User *u = find_user(bank, arg1);

		if (!u)
		{
			send_secure_response(bank, "No such user\n");
			return;
		}

		char *amt_str = arg2;
		char *extra = strtok(NULL, " ");
		if (!amt_str || extra)
		{
			send_secure_response(bank, "Usage: withdraw <amt>\n");
			return;
		}

		if (!matches_regex(amt_str, "^[0-9]+$"))
		{
			send_secure_response(bank, "Usage: withdraw <amt>\n");
			return;
		}

		int amt = atoi(amt_str);
		if (amt < 0) // Just in case
		{
			send_secure_response(bank, "Usage: withdraw <amt>\n");
			return;
		}

		if (amt > u->balance)
		{
			send_secure_response(bank, "Insufficient funds\n");
			return;
		}

		// Proceed with withdrawal
		u->balance -= amt;

		char response[100];
		snprintf(response, sizeof(response), "$%d dispensed\n", amt);
		// printf("[BANK] Dispensing: %s", response);
		send_secure_response(bank, response);
	}

	else if (cmd && strcmp(cmd, "balance") == 0 && arg1)
	{
		User *u = find_user(bank, arg1);

		if (u)
		{
			char response[100];
			snprintf(response, sizeof(response), "$%d\n", u->balance);
			// printf("[BANK] Sending balance to secure response: %s", response);
			send_secure_response(bank, response); // Use secure response
		}
		else
		{
			send_secure_response(bank, "No such user\n"); // Use secure response
		}
	}
	else if (cmd && strcmp(cmd, "check-user") == 0 && arg1)
	{
		User *u = find_user(bank, arg1);
		if (u)
		{
			send_secure_response(bank, "User exists\n");
		}
		else
		{
			send_secure_response(bank, "No such user\n");
		}
	}
	else
	{
		bank_send(bank, "Invalid command\n", strlen("Invalid command\n"));
	}
	free(cmd_copy);
}
