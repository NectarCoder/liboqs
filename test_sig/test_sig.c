#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main(int argc, char *argv[]) {
    // Initialize OQS
    OQS_init();

    // Select algorithm: from compile-time macro or command-line argument
    const char *alg;
#ifdef ALGORITHM
    alg = ALGORITHM;
#else
    if (argc < 2) {
        printf("Usage: %s <algorithm>\n", argv[0]);
        return EXIT_FAILURE;
    }
    alg = argv[1];
#endif
    printf("Using algorithm: %s\n", alg);
    // Create a new signature object for the specified algorithm
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (sig == NULL) {
        printf("ERROR: Signature algorithm not enabled\n");
        return EXIT_FAILURE;
    }

    // Get the lengths for the keys and signature
    printf("Public key length: %zu bytes\n", sig->length_public_key);
    printf("Secret key length: %zu bytes\n", sig->length_secret_key);
    printf("Maximum signature length: %zu bytes\n", sig->length_signature);

    // Allocate memory for keys and signature
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    /*size_t ten_mb = 10 * 1024 * 1024;
    uint8_t *public_key = malloc(ten_mb);
    uint8_t *secret_key = malloc(ten_mb);
    uint8_t *signature = malloc(ten_mb);
    if (public_key == NULL || secret_key == NULL || signature == NULL) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        return EXIT_FAILURE;
    }*/
    
    // Generate keypair
    OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        printf("ERROR: Key generation failed\n");
        return EXIT_FAILURE;
    }
    printf("Keys generated successfully!\n");

    // Message to sign
    const char *message = "Hello Quantum World!";
    size_t message_len = strlen(message);
    size_t signature_len;

    // Sign the message
    rc = OQS_SIG_sign(sig, signature, &signature_len, 
                      (uint8_t*)message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        printf("ERROR: Signing failed\n");
        return EXIT_FAILURE;
    }
    printf("Message signed successfully!\n");
    printf("Signature length: %zu bytes\n", signature_len);

    // Verify the signature
    rc = OQS_SIG_verify(sig, (uint8_t*)message, message_len,
                        signature, signature_len, public_key);
    if (rc != OQS_SUCCESS) {
        printf("ERROR: Signature verification failed\n");
        return EXIT_FAILURE;
    }
    printf("Signature verified successfully!\n");

    // Clean up
    OQS_MEM_secure_free(secret_key, sig->length_secret_key);
    printf("Secret key securely freed from memory.\n");
    OQS_MEM_insecure_free(public_key);
    printf("Public key freed from memory.\n");
    OQS_MEM_insecure_free(signature);
    printf("Signature freed from memory.\n");
    OQS_SIG_free(sig);
    printf("Signature object freed from memory.\n");
    OQS_destroy();
    printf("OQS resources destroyed.\n");

    return EXIT_SUCCESS;
}
