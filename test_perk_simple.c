#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main() {
    printf("Testing PERK algorithm directly...\n");
    
    OQS_SIG *sig = OQS_SIG_new("PERK-128-fast-3");
    if (sig == NULL) {
        printf("ERROR: OQS_SIG_new failed\n");
        return 1;
    }
    
    printf("Algorithm: %s\n", sig->method_name);
    printf("Public key length: %zu\n", sig->length_public_key);
    printf("Secret key length: %zu\n", sig->length_secret_key);
    printf("Signature length: %zu\n", sig->length_signature);
    
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    uint8_t message[] = "Hello, PERK!";
    size_t message_len = strlen((char*)message);
    size_t signature_len;
    
    if (!public_key || !secret_key || !signature) {
        printf("ERROR: Memory allocation failed\n");
        goto cleanup;
    }
    
    printf("Generating keypair...\n");
    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        printf("ERROR: Keypair generation failed\n");
        goto cleanup;
    }
    printf("Keypair generation: SUCCESS\n");
    
    printf("Signing message...\n");
    if (OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key) != OQS_SUCCESS) {
        printf("ERROR: Signing failed\n");
        goto cleanup;
    }
    printf("Signing: SUCCESS (signature length: %zu)\n", signature_len);
    
    printf("Verifying signature...\n");
    if (OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key) != OQS_SUCCESS) {
        printf("ERROR: Verification failed\n");
        goto cleanup;
    }
    printf("Verification: SUCCESS\n");
    
    printf("All tests passed!\n");

cleanup:
    free(public_key);
    free(secret_key);
    free(signature);
    OQS_SIG_free(sig);
    return 0;
}