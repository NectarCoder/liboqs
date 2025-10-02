#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main(int argc, char *argv[]) {
    int exit_code = EXIT_FAILURE;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *signature = NULL;
    uint8_t *large_message = NULL;
    size_t secret_key_len = 0;

    // Initialize OQS
    OQS_init();

    // Select algorithm: from compile-time macro or command-line argument
    const char *alg;
#ifdef ALGORITHM
    alg = ALGORITHM;
#else
    if (argc < 2) {
        printf("Usage: %s <algorithm>\n", argv[0]);
        goto cleanup;
    }
    alg = argv[1];
#endif
    printf("Using algorithm: %s\n", alg);
    // Create a new signature object for the specified algorithm
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (sig == NULL) {
        printf("ERROR: Signature algorithm not enabled\n");
        goto cleanup;
    }

    // Get the lengths for the keys and signature
    printf("Public key length: %zu bytes\n", sig->length_public_key);
    printf("Secret key length: %zu bytes\n", sig->length_secret_key);
    printf("Maximum signature length: %zu bytes\n", sig->length_signature);

    secret_key_len = sig->length_secret_key;

    // Allocate memory for keys and signature
    public_key = malloc(sig->length_public_key);
    secret_key = malloc(sig->length_secret_key);
    signature = malloc(sig->length_signature);
    if (public_key == NULL || secret_key == NULL || signature == NULL) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        goto cleanup;
    }

    // Generate keypair
    OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        printf("ERROR: Key generation failed\n");
        goto cleanup;
    }
    printf("Keys generated successfully!\n");

    // Prepare messages
    const char *small_message = "Hello Quantum World!";
    size_t small_message_len = strlen(small_message);
    printf("Small message length: %zu bytes\n", small_message_len);

    const size_t repeats = 256;
    size_t large_message_len = small_message_len * repeats;
    large_message = malloc(large_message_len);
    if (large_message == NULL) {
        fprintf(stderr, "ERROR: Memory allocation failed for large message\n");
        goto cleanup;
    }
    for (size_t i = 0; i < repeats; ++i) {
        memcpy(large_message + i * small_message_len, small_message, small_message_len);
    }
    printf("Large message length: %zu bytes\n", large_message_len);

    size_t signature_len = 0;

    // Sign and verify the small message
    rc = OQS_SIG_sign(sig, signature, &signature_len,
                      (const uint8_t *)small_message, small_message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        printf("ERROR: Signing small message failed\n");
        goto cleanup;
    }
    size_t signature_len_small = signature_len;
    printf("Signature length (small message): %zu bytes\n", signature_len_small);

    rc = OQS_SIG_verify(sig, (const uint8_t *)small_message, small_message_len,
                        signature, signature_len_small, public_key);
    if (rc != OQS_SUCCESS) {
        printf("ERROR: Signature verification failed for small message\n");
        goto cleanup;
    }
    printf("Small message signature verified successfully!\n");

    // Sign and verify the large message
    rc = OQS_SIG_sign(sig, signature, &signature_len,
                      large_message, large_message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        printf("ERROR: Signing large message failed\n");
        goto cleanup;
    }
    size_t signature_len_large = signature_len;
    printf("Signature length (large message): %zu bytes\n", signature_len_large);

    if (signature_len_large != signature_len_small) {
        printf("ERROR: Signature length changed with message size (%zu vs %zu)\n",
               signature_len_small, signature_len_large);
        goto cleanup;
    }

    rc = OQS_SIG_verify(sig, large_message, large_message_len,
                        signature, signature_len_large, public_key);
    if (rc != OQS_SUCCESS) {
        printf("ERROR: Signature verification failed for large message\n");
        goto cleanup;
    }
    printf("Large message signature verified successfully!\n");
    printf("Signature length is consistent across message sizes (%zu bytes).\n", signature_len_small);

    exit_code = EXIT_SUCCESS;

cleanup:
    if (secret_key != NULL) {
        OQS_MEM_secure_free(secret_key, secret_key_len);
        printf("Secret key securely freed from memory.\n");
    }
    if (public_key != NULL) {
        OQS_MEM_insecure_free(public_key);
        printf("Public key freed from memory.\n");
    }
    if (signature != NULL) {
        OQS_MEM_insecure_free(signature);
        printf("Signature freed from memory.\n");
    }
    free(large_message);
    if (sig != NULL) {
        printf("Signature object freed from memory.\n");
    }
    OQS_SIG_free(sig);
    OQS_destroy();
    printf("OQS resources destroyed.\n");

    return exit_code;
}
