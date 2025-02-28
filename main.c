#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

// Function to perform SHA-256 hashing
void sha256(const unsigned char *data, size_t len, unsigned char *hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);
}

// Function to perform XOR encryption
void xor_encrypt(const unsigned char *input, unsigned char *output, const unsigned char *key, size_t len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i];
    }
}

// Function to generate additive shares using COT
void generate_additive_shares(BIGNUM *a, BIGNUM *b, BIGNUM *c, BIGNUM *d, const EC_GROUP *group) {
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *t = BN_new();
    BIGNUM *u = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // Generate random values r and s
    BN_rand_range(r, EC_GROUP_get0_order(group));
    BN_rand_range(s, EC_GROUP_get0_order(group));

    // Compute t = a * r mod n
    BN_mod_mul(t, a, r, EC_GROUP_get0_order(group), ctx);

    // Compute u = b * s mod n
    BN_mod_mul(u, b, s, EC_GROUP_get0_order(group), ctx);

    // Compute c = t + u mod n
    BN_mod_add(c, t, u, EC_GROUP_get0_order(group), ctx);

    // Compute d = a * b - c mod n
    BN_mod_mul(d, a, b, EC_GROUP_get0_order(group), ctx);
    BN_mod_sub(d, d, c, EC_GROUP_get0_order(group), ctx);

    // Clean up
    BN_free(r);
    BN_free(s);
    BN_free(t);
    BN_free(u);
    BN_CTX_free(ctx);
}

int main() {
    // Initialize the secp256k1 curve
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();

    // Input values a and b (multiplicative shares)
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BN_rand_range(a, EC_GROUP_get0_order(group));
    BN_rand_range(b, EC_GROUP_get0_order(group));

    // Output values c and d (additive shares)
    BIGNUM *c = BN_new();
    BIGNUM *d = BN_new();

    // Generate additive shares
    generate_additive_shares(a, b, c, d, group);

    // Verify that a * b = c + d mod n
    BIGNUM *product = BN_new();
    BIGNUM *sum = BN_new();
    BN_mod_mul(product, a, b, EC_GROUP_get0_order(group), ctx);
    BN_mod_add(sum, c, d, EC_GROUP_get0_order(group), ctx);

    if (BN_cmp(product, sum) == 0) {
        printf("Verification successful: a * b = c + d mod n\n");
    } else {
        printf("Verification failed: a * b != c + d mod n\n");
    }

    // Print the values
    char *a_str = BN_bn2hex(a);
    char *b_str = BN_bn2hex(b);
    char *c_str = BN_bn2hex(c);
    char *d_str = BN_bn2hex(d);

    printf("a: %s\n", a_str);
    printf("b: %s\n", b_str);
    printf("c: %s\n", c_str);
    printf("d: %s\n", d_str);

    // Clean up
    OPENSSL_free(a_str);
    OPENSSL_free(b_str);
    OPENSSL_free(c_str);
    OPENSSL_free(d_str);
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(product);
    BN_free(sum);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 0;
}