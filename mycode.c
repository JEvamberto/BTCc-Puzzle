#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <time.h>

// Target Bitcoin address to match
const char* target_address = "1Hoyt6UBzwL5vvUSTLMQC2mwvvE5PpeSC";

// Function to generate a random private key (32 bytes)
void generate_random_private_key(unsigned char* private_key, size_t len) {
    for (size_t i = 0; i < len; i++) {
        private_key[i] = rand() % 256;
    }
}

void generate_random_private_key_desafio(unsigned char* private_key){
    float f;
    private_key[14]=64+(rand() % 16);
    private_key[15]=176+(rand() % 16);
    private_key[19]=96+(rand()%16);
    private_key[21]=112+(rand()%16);
    private_key[24]=64+(rand() % 16);
    private_key[25]=rand()%16; // pode ser 0x0x, útimo x pode ser a-f ou 0-9, Além disso 0xa é igual a 0x0a
    private_key[26]=128+(rand()% 16);
    private_key[27]=48+(rand()%16);

    private_key[28]=57+(rand()%7);
    private_key[29]=48+(rand()%16);
    //[31]=[30]+3
    /*f=(rand()%13);
    private_key[30]=112+f;
    private_key[31]=48+(f+3);*/


}

// Function to perform SHA-256
void sha256(const unsigned char* data, size_t len, unsigned char* output) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(output, &sha256);
}

// Function to perform RIPEMD-160
void ripemd160(const unsigned char* data, size_t len, unsigned char* output) {
    RIPEMD160_CTX ripemd;
    RIPEMD160_Init(&ripemd);
    RIPEMD160_Update(&ripemd, data, len);
    RIPEMD160_Final(output, &ripemd);
}

// Function to perform Base58Check encoding (simple implementation)
void base58_encode(const unsigned char* input, size_t input_len, char* output) {
    const char* base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    unsigned char digits[50] = {0};
    size_t digit_len = 1;

    for (size_t i = 0; i < input_len; i++) {
        int carry = input[i];
        for (size_t j = 0; j < digit_len; j++) {
            carry += 256 * digits[j];
            digits[j] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            digits[digit_len++] = carry % 58;
            carry /= 58;
        }
    }

    int leading_zeroes = 0;
    while (leading_zeroes < input_len && input[leading_zeroes] == 0) {
        output[leading_zeroes++] = '1';
    }

    for (size_t i = 0; i < digit_len; i++) {
        output[leading_zeroes + i] = base58_alphabet[digits[digit_len - 1 - i]];
    }
    output[leading_zeroes + digit_len] = '\0';
}

// Function to generate Bitcoin address from the public key
void generate_bitcoin_address(const unsigned char* public_key, size_t public_key_len, char* bitcoin_address) {
    // Step 1: Perform SHA-256 on the public key
    unsigned char sha256_hash[32];
    sha256(public_key, public_key_len, sha256_hash);

    // Step 2: Perform RIPEMD-160 on the SHA-256 hash
    unsigned char ripemd160_hash[20];
    ripemd160(sha256_hash, 32, ripemd160_hash);

    // Step 3: Add version byte (0x00 for mainnet) to create payload
    unsigned char versioned_payload[21];
    versioned_payload[0] = 0x00;  // Version byte for mainnet
    memcpy(versioned_payload + 1, ripemd160_hash, 20);

    // Step 4: Perform double SHA-256 on the versioned payload
    unsigned char double_sha256[32];
    sha256(versioned_payload, 21, double_sha256);
    sha256(double_sha256, 32, double_sha256);  // Double SHA-256

    // Step 5: Append first 4 bytes of double SHA-256 as checksum
    unsigned char address_bytes[25];
    memcpy(address_bytes, versioned_payload, 21);
    memcpy(address_bytes + 21, double_sha256, 4);  // Add checksum

    // Step 6: Encode address bytes in Base58Check
    base58_encode(address_bytes, 25, bitcoin_address);
}

void print_private_key(const unsigned char* private_key, size_t key_len) {
    printf("Private key: ");
    for (size_t i = 0; i < key_len; i++) {
        printf("%02x", private_key[i]);
    }
    printf("\n");
}

int main() {
    // Seed random number generator
    srand(time(NULL));

    //Initialize secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    //Loop until the Bitcoin address matches the target address
    char generated_address[50];
    int match_found = 0;
    int iterations = 0;
    unsigned long keys_processed = 0;
    time_t start_time = time(NULL);
   //403b3d4fcff56a92f335a0cf570e4xbxb17b2a6x867x8xax4x0x8x3x3x3x7x3x

    
    unsigned char private_key[32] = {
          0x40,0x3b,0x3d,0x4f,0xcf,0xf5,0x6a,0x92,
          0xf3,0x35,0xa0,0xcf,0x57,0x0e,0x40,0xb0,
          0xb1,0x7b,0x2a,0x60,0x86,0x70,0x86,0xa8,
          0x40,0x00,0x80,0x30,0x30,0x30,0x74,0x37
    };

    /*printf("\nChave privada antes da geração aleatória\n");
        print_private_key(private_key,sizeof(private_key));
    printf("\nChave privada depois da geração aleatória\n");
        generate_random_private_key_desafio(private_key);
        print_private_key(private_key,sizeof(private_key));
        generate_random_private_key_desafio(private_key);
        print_private_key(private_key,sizeof(private_key));*/
    
        
      


    while (!match_found) {
      
        //print_private_key(private_key,sizeof(private_key));
        generate_random_private_key_desafio(private_key);
        /*
        // Increment the private key
            for (int i = 31; i >= 0; i--) {
                if (++private_key[i] != 0) break;  // Stop incrementing if no overflow
            }  */

        // Generate a random private key
        //generate_random_private_key(private_key, sizeof(private_key));

        // Step 2: Generate public key from private key
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
            // If public key generation fails, skip this key and generate a new one
            continue;
        }

        // Step 3: Serialize the public key (uncompressed format)
        unsigned char pubkey_serialized[65];
        size_t pubkey_len = sizeof(pubkey_serialized);
        secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);

        // Generate Bitcoin address from the serialized public key
        generate_bitcoin_address(pubkey_serialized, pubkey_len, generated_address);

        // Compare generated address with target address
        if (strcmp(generated_address, target_address) == 0) {
            printf("Match found!\n");
            printf("Private Key: ");
            for (int i = 0; i < 32; i++) {
                printf("%02x", private_key[i]);
            }
            printf("\n");
            printf("Bitcoin Address: %s\n", generated_address);
            match_found = 1;
        }

        keys_processed++;
        iterations++;

        // Calculate keys per second every 1 second
        time_t current_time = time(NULL);
        if (current_time > start_time) {
            double elapsed_seconds = difftime(current_time, start_time);
            double keys_per_second = keys_processed / elapsed_seconds;
            printf("%d address checked; (%.2f keys/sec); last_pk: ",iterations, keys_per_second);
            print_private_key(private_key, sizeof(private_key));
            start_time = current_time;  // Reset the time for the next interval
            keys_processed = 0;  // Reset key counter for the next second
        }
    }

    // Clean up secp256k1 context
    secp256k1_context_destroy(ctx);

    return 0;
}
