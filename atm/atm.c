#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>

ATM *atm_create(const char *atm_file_path)
{

    FILE *fp = fopen(atm_file_path, "r"); // opens reads teh file
    if (!fp)
    {
        return NULL; // main() will print the error and exit
    }

    // Read full file into buffer
    // fseek - this moves file pointer to the end of file
    fseek(fp, 0, SEEK_END);
    // after fseek, ftell(fp) tells me the how many bytes into file you are
    long fsize = ftell(fp);
    // reset pointer to the begining
    fseek(fp, 0, SEEK_SET);

    // we create a buffer that will store the passed in data in file
    char *buffer = malloc(fsize + 1);
    // read bytes fomr file into memory buffer
    fread(buffer, 1, fsize, fp);
    // set last bit to null char
    buffer[fsize] = '\0';
    fclose(fp);

    ATM *atm = (ATM *)malloc(sizeof(ATM));
    if (atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    bzero(&atm->rtr_addr, sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port = htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd, (struct sockaddr *)&atm->atm_addr, sizeof(atm->atm_addr));

    // Set up the protocol state
    // TODO set up more, as needed

    // --- Parse ATM private key ---
    BIO *priv_bio = BIO_new_mem_buf(buffer, -1);
    atm->private_key = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL); // Updated API
    BIO_free(priv_bio);
    if (!atm->private_key)
    {
        fprintf(stderr, "Failed to load ATM private key\n");
        free(buffer);
        free(atm);
        return NULL;
    }

    // --- Parse Bank public key ---
    char *bank_pub_start = strstr(buffer, "-----BEGIN PUBLIC KEY-----");
    if (!bank_pub_start)
    {
        fprintf(stderr, "Bank public key block not found\n");
        free(buffer);
        free(atm);
        return NULL;
    }
    BIO *pub_bio = BIO_new_mem_buf(bank_pub_start, -1);
    atm->bank_public_key = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL); // Updated API
    BIO_free(pub_bio);
    if (!atm->bank_public_key)
    {
        fprintf(stderr, "Failed to load Bank public key\n");
        free(buffer);
        free(atm);
        return NULL;
    }

    // --- Parse AES key ---
    char *aes_key_line = strstr(buffer, "AES_KEY=");
    if (!aes_key_line)
    {
        fprintf(stderr, "AES key line not found\n");
        free(buffer);
        free(atm);
        return NULL;
    }
    aes_key_line += strlen("AES_KEY=");
    char *newline = strchr(aes_key_line, '\n');
    if (newline)
        *newline = '\0';

    unsigned char aes_key_bin[32];
    int decoded_len = EVP_DecodeBlock(aes_key_bin, (const unsigned char *)aes_key_line, strlen(aes_key_line));

    // EVP_DecodeBlock may return extra padding; manually strip
    if (decoded_len <= 0)
    {
        fprintf(stderr, "AES key decode failed\n");
        free(buffer);
        free(atm);
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
        free(atm);
        return NULL;
    }

    // Copy the decoded AES key into the ATM's AES key field
    memcpy(atm->aes_key, aes_key_bin, 32);
    free(buffer);

    atm->session_active = 0;
    atm->session_user[0] = '\0';

    return atm;
}

void atm_free(ATM *atm)
{
    if (atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

int matches_regex(const char *string, const char *pattern)
{
    regex_t regex;
    int result;

    result = regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB);
    if (result)
        return 0;

    result = regexec(&regex, string, 0, NULL, 0);
    regfree(&regex);

    return result == 0;
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr *)&atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

int send_secure_command(ATM *atm, const char *plaintext_command)
{
    unsigned char iv[16];
    unsigned char tag[16];
    unsigned char ciphertext[1000];
    unsigned char c_key[256]; // RSA-encrypted AES key
    unsigned char signature[256];

    int ciphertext_len = 0;
    size_t c_key_len = sizeof(c_key);

    // Generate a random IV
    if (!RAND_bytes(iv, sizeof(iv)))
    {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }

    // AES-GCM Encrypt the command
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return -1;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
        return -1;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, atm->aes_key, iv))
        return -1;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext_command, strlen(plaintext_command)))
        return -1;
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag))
        return -1;
    EVP_CIPHER_CTX_free(ctx);

    // Sign ciphertext with ATM private key
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, atm->private_key))
    {
        fprintf(stderr, "Failed to initialize signature\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    if (!EVP_DigestSignUpdate(mdctx, ciphertext, ciphertext_len))
        return -1;

    size_t sig_len = sizeof(signature);
    if (!EVP_DigestSignFinal(mdctx, signature, &sig_len))
        return -1;

    EVP_MD_CTX_free(mdctx);

    // Encrypt AES key with Bank public key
    // EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(atm->bank_public_key, NULL);
    // if (!pctx || EVP_PKEY_encrypt_init(pctx) <= 0 ||
    //     EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
    //     EVP_PKEY_encrypt(pctx, c_key, &c_key_len, atm->aes_key, 32) <= 0)
    // {
    //     fprintf(stderr, "Failed to encrypt AES key\n");
    //     EVP_PKEY_CTX_free(pctx);
    //     return -1;
    // }
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(atm->bank_public_key, NULL);
    if (!pctx || EVP_PKEY_encrypt_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_encrypt(pctx, c_key, &c_key_len, atm->aes_key, 32) <= 0)
    {
        fprintf(stderr, "Failed to encrypt AES key\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);

    // Assemble final packet
    size_t total_len = c_key_len + ciphertext_len + sig_len + sizeof(tag) + sizeof(iv);
    unsigned char *packet = malloc(total_len);
    if (!packet)
        return -1;

    size_t offset = 0;
    memcpy(packet + offset, c_key, c_key_len);
    offset += c_key_len;
    memcpy(packet + offset, ciphertext, ciphertext_len);
    offset += ciphertext_len;
    memcpy(packet + offset, signature, sig_len);
    offset += sig_len;
    memcpy(packet + offset, tag, sizeof(tag));
    offset += sizeof(tag);
    memcpy(packet + offset, iv, sizeof(iv));
    offset += sizeof(iv);

    // Send to bank
    int sent = atm_send(atm, (char *)packet, total_len);
    free(packet);
    return sent;
}

int receive_secure_response(ATM *atm, char *plaintext_response, size_t max_len)
{
    unsigned char ciphertext[1000];
    unsigned char signature[256];
    unsigned char tag[16];
    unsigned char iv[16];

    // Receive the encrypted response
    // After receiving packet
    char packet[1500];
    int n = atm_recv(atm, packet, sizeof(packet));
    if (n < 0)
    {
        fprintf(stderr, "Failed to receive response from bank\n");
        return -1;
    }

    // DEBUG: Total received bytes
    // printf("[DEBUG] Total bytes received: %d\n", n);

    // Extract components
    size_t offset = 0;
    size_t ciphertext_len = n - 256 - 16 - 16; // 256 = sig, 16 = tag, 16 = iv
    // printf("[DEBUG] Calculated ciphertext_len: %zu\n", ciphertext_len);

    // Extract data sections
    memcpy(ciphertext, packet + offset, ciphertext_len);
    offset += ciphertext_len;
    memcpy(signature, packet + offset, 256);
    offset += 256;
    memcpy(tag, packet + offset, 16);
    offset += 16;
    memcpy(iv, packet + offset, 16);
    offset += 16;

    // Print IV and Tag
    // printf("[DEBUG] IV: ");
    // for (int i = 0; i < 16; i++)
    //     printf("%02x", iv[i]);
    // printf("\n");

    // printf("[DEBUG] Tag: ");
    // for (int i = 0; i < 16; i++)
    //     printf("%02x", tag[i]);
    // printf("\n");

    // Verify the signature
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, atm->bank_public_key) ||
        !EVP_DigestVerifyUpdate(mdctx, ciphertext, ciphertext_len) ||
        EVP_DigestVerifyFinal(mdctx, signature, 256) != 1)
    {
        fprintf(stderr, "Signature verification failed\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);

    // Decrypt the ciphertext
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plaintext_len = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) ||
        !EVP_DecryptInit_ex(ctx, NULL, NULL, atm->aes_key, iv) ||
        !EVP_DecryptUpdate(ctx, (unsigned char *)plaintext_response, &len, ciphertext, ciphertext_len))
    {
        fprintf(stderr, "AES-GCM decryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);
    // printf("[DEBUG] Attempting AES-GCM decryption finalize\n");
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext_response + len, &len) <= 0)
    {
        fprintf(stderr, "AES-GCM decryption failed (finalize)\n");

        // Optional: print suspicious data
        // printf("[DEBUG] Decryption context info:\n");
        // printf(" - Ciphertext length: %zu\n", ciphertext_len);
        // printf(" - Key (first 8 bytes): ");
        // for (int i = 0; i < 8; i++)
        //     printf("%02x", atm->aes_key[i]);
        // printf("\n");

        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    plaintext_response[plaintext_len] = '\0'; // Null-terminate the plaintext
    return plaintext_len;
}

void atm_process_command(ATM *atm, char *command)
{
    // Debug: Log the raw command received
    // printf("[DEBUG] Received command: '%s'\n", command);

    // Remove trailing newline from the command
    command[strcspn(command, "\n")] = '\0';
    // printf("[DEBUG] Sanitized command: '%s'\n", command);

    // Check for empty command
    if (strlen(command) == 0)
    {
        // printf("[DEBUG] Empty command received\n");
        return;
    }

    // Process "begin-session" command
    if (strncmp(command, "begin-session ", 14) == 0)
    {
        // printf("[DEBUG] begin-session matched\n");

        if (atm->session_active)
        {
            // printf("[DEBUG] A session is already active for user: '%s'\n", atm->session_user);
            printf("A user is already logged in\n");
            return;
        }

        // Extract username
        char *username = command + 14; // Skip "begin-session " (14 chars + 1 space)
        // printf("[DEBUG] Extracted username: '%s'\n", username);

        // Validate username format
        if (!matches_regex(username, "^[a-zA-Z]+$"))
        {
            // printf("[DEBUG] Username '%s' does not match regex\n", username);
            printf("Usage: begin-session <user-name>\n");
            return;
        }

        // Attempt to open the user's card file
        char filename[300];
        snprintf(filename, sizeof(filename), "%s.card", username);
        // printf("[DEBUG] Looking for card file: '%s'\n", filename);

        // check if user exists before checking for card file
        char check_user[300];
        snprintf(check_user, sizeof(check_user), "check-user %s", username);
        if (send_secure_command(atm, check_user) < 0)
        {
            // printf("[DEBUG] Failed to send check-user command\n");
            printf("No such user\n");
            return;
        }
        char check_user_reply[1000];
        int user_n = receive_secure_response(atm, check_user_reply, sizeof(check_user_reply));
        if (user_n < 0)
        {
            // printf("[DEBUG] Failed to receive reply from bank\n");
            printf("No such user\n");
            return;
        }
        check_user_reply[user_n] = '\0';
        if (strcmp(check_user_reply, "No such user\n") == 0)
        {
            // printf("[DEBUG] User '%s' does not exist\n", username);
            printf("No such user\n");
            return;
        }

        FILE *fp = fopen(filename, "r");
        if (!fp)
        {
            // printf("[DEBUG] Failed to open card file for user: '%s'\n", username);
            printf("Unable to access %s's card\n", username);
            return;
        }

        // Read username from the card file
        char card_user[251];
        if (!fgets(card_user, sizeof(card_user), fp))
        {
            // printf("[DEBUG] Failed to read from card file: '%s'\n", filename);
            fclose(fp);
            printf("Unable to access %s's card\n", username);
            return;
        }
        fclose(fp);
        card_user[strcspn(card_user, "\n")] = '\0'; // Remove trailing newline
        // printf("[DEBUG] Read from card file: '%s'\n", card_user);

        // Verify the username matches the card file
        if (strcmp(card_user, username) != 0)
        {
            // printf("[DEBUG] Username in card file ('%s') does not match provided username ('%s')\n", card_user, username);
            printf("No such user\n");
            return;
        }

        // Ask for the PIN
        // printf("[DEBUG] Asking for PIN\n");
        printf("PIN? ");
        fflush(stdout);

        char pin[10];
        if (!fgets(pin, sizeof(pin), stdin))
        {
            // printf("[DEBUG] Failed to read PIN from stdin\n");
            printf("Not authorized\n");
            return;
        }

        // Remove trailing newline from the PIN
        pin[strcspn(pin, "\n")] = '\0';
        // printf("[DEBUG] Received PIN: '%s'\n", pin);

        // Validate PIN format (exactly 4 digits)
        if (!matches_regex(pin, "^[0-9]{4}$"))
        {
            // printf("[DEBUG] PIN '%s' does not match regex (must be 4 digits)\n", pin);
            printf("Not authorized\n");
            return;
        }

        // Send secure login command to the bank
        char msg[300];
        snprintf(msg, sizeof(msg), "login %s %s", username, pin);
        // printf("[DEBUG] Sending login command to bank: '%s'\n", msg);

        if (send_secure_command(atm, msg) < 0)
        {
            // printf("[DEBUG] Failed to send secure command to bank\n");
            printf("Not authorized\n");
            return;
        }

        // Wait for the bank's reply
        char reply[1000];
        int n = atm_recv(atm, reply, sizeof(reply));
        if (n < 0)
        {
            // printf("[DEBUG] Failed to receive reply from bank\n");
            printf("Not authorized\n");
            return;
        }
        reply[n] = '\0';
        // printf("[DEBUG] Received reply from bank: '%s'\n", reply);

        // Process the bank's reply
        if (strcmp(reply, "Authorized\n") == 0)
        {
            atm->session_active = 1;
            strncpy(atm->session_user, username, 250);
            atm->session_user[250] = '\0';
            // printf("[DEBUG] User '%s' authorized\n", username);
            printf("Authorized\n");
        }
        else
        {
            // printf("[DEBUG] Bank reply indicates user '%s' is not authorized\n", username);
            printf("Not authorized\n");
        }
    }
    else if (strncmp(command, "withdraw ", 9) == 0)
    {
        if (!atm->session_active)
        {
            printf("No user is logged in\n");
            return;
        }

        char *amt_str = command + 9;

        // Strip newline and validate
        amt_str[strcspn(amt_str, "\n")] = '\0';

        if (!matches_regex(amt_str, "^[0-9]+$"))
        {
            printf("Usage: withdraw <amt>\n");
            return;
        }

        // Format secure withdraw message: "withdraw <user> <amt>"
        char msg[300];
        snprintf(msg, sizeof(msg), "withdraw %s %s", atm->session_user, amt_str);

        if (send_secure_command(atm, msg) < 0)
        {
            printf("Failed to send withdraw request\n");
            return;
        }

        char plaintext_response[1000];
        int response_len = receive_secure_response(atm, plaintext_response, sizeof(plaintext_response));
        if (response_len < 0)
        {
            printf("Failed to receive withdraw response\n");
            return;
        }

        plaintext_response[response_len] = '\0';
        // printf("[DEBUG] Received reply from bank: %s\n", plaintext_response);
        printf("%s", plaintext_response);
    }
    else if (strncmp(command, "balance", 7) == 0)
    {
        if (atm->session_active != 1)
        {
            printf("No user is logged in\n");
            return;
        }
        if (strlen(command) > 7)
        {
            printf("Usage: balance\n");
            return;
        }

        char buffer[300];
        snprintf(buffer, sizeof(buffer), "balance %s", atm->session_user);
        send_secure_command(atm, buffer);

        char plaintext_response[1000];
        int response_len = receive_secure_response(atm, plaintext_response, sizeof(plaintext_response));
        if (response_len < 0)
        {
            printf("Failed to retrieve balance\n");
            return;
        }

        // Null-terminate the plaintext response
        plaintext_response[response_len] = '\0';

        // printf("[DEBUG] Received reply from bank: %s\n", plaintext_response);
        printf("%s", plaintext_response);
    }
    else if (strncmp(command, "end-session", 11) == 0)
    {
        if (atm->session_active != 1)
        {
            printf("No user is logged in\n");
            return;
        }
        if (strlen(command) > 11)
        {
            printf("Usage: end-session\n");
            return;
        }

        atm->session_active = 0;

        printf("User logged out\n");
    }

    else
    {
        // printf("[DEBUG] Invalid or unsupported command: '%s'\n", command);
        printf("Invalid command\n");
    }
}
