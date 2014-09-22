#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_all_modes.h"
#include "generic_tools.h"

#define MAXLINE_VEC         2048
#define VAL_MAX_SIZE_VEC    2000
#define ID_MAX_SIZE_VEC     48

/**
 * 
 * \param[out]  is_last_vector  Status flag stating if the fetched vector was the last one in the file.
 * \return  0 if end of file
 *          1 if not
 */
void get_next_vector(FILE* file, AES_mode* mode, AES_crypt_type* crypt, AES_input* in, AES_res* exp_out, int* is_last_vector);

/**
 * Convert a string to the enum element it describes.
 */
AES_crypt_type crypt_type_strtoenum(const char* str);

/**
 * Convert a string to the enum element it describes.
 */
AES_mode ase_mode_strtoenum(const char* str);

int main(int argc, char** argv)
{
    init_aes_wrapper();
    
    int i;
    unsigned char*  source = malloc(48);
    unhexify(source, "08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002");
    unsigned char*  iv = malloc(12);
    unhexify(iv, "12153524C0895E81B2C28465");
    unsigned char*  aad = malloc(28);
    unhexify(aad, "D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81");
    unsigned char*  key = malloc(16);
    unhexify(key, "AD7A2BD03EAC835A6F620FDCB506B345");
    unsigned char*  tag = malloc(16);
    unsigned char*  output;
    int* output_size = malloc(sizeof(int));
    AES_mode        mode = AES_GCM;
    AES_crypt_type  crypt = ENCRYPT;
    aes_gcm(crypt, key, 16, iv, 12, source, 48, aad, 28, 16, tag, &output, output_size);
    printf("returned from aes_gcm.\n");
    printf("Output(%d): 0x", *output_size);
    for(i=0; i<*output_size; ++i)
        printf("%02X", output[i]);
    printf("\n");
    
    
    FILE* fp = fopen(argv[1], "r");
    if(fp == NULL) {
        fprintf(stderr, "Could not open stimuli file. Aborting.\n");
        return EXIT_FAILURE;
    }
    else {
        AES_res*        aes_exp_res = malloc(sizeof(AES_res));
        // printf("Address of aes_exp_res->tag: %016X\n", &(aes_exp_res->tag));
        // printf("Address of aes_exp_res->tag_size: %016X\n", &(aes_exp_res->tag_size));
        // printf("Address of aes_exp_res->output: %016X\n", &(aes_exp_res->output));
        AES_res*        aes_res = malloc(sizeof(AES_res));
        AES_input*      aes_in = malloc(sizeof(AES_input));
        // aes_in->aad = malloc(64);
        AES_mode        mode;
        AES_crypt_type  crypt;
        int is_last_vector = 0;
        printf("Parse the test vector file.\n");
        while(!is_last_vector) {
            get_next_vector(fp, &mode, &crypt, aes_in, aes_exp_res, &is_last_vector);
            printf("Source(%d): 0x", aes_in->source_size);
            for(i=0; i<aes_in->source_size; ++i)
                printf("%02X", aes_in->source[i]);
            printf("\n");
            printf("key(%d): 0x", aes_in->key_size);
            for(i=0; i<aes_in->key_size; ++i)
                printf("%02X", aes_in->key[i]);
            printf("\n");
            aes_res->tag_size = aes_exp_res->tag_size;
            aes_wrapper(mode, crypt, aes_in, aes_res);
            printf("Back from aes wrapper.\n");
            printf("Output: \t\t\t0x");
            for(i=0; i<aes_res->output_size; ++i)
                printf("%02X",aes_res->output[i]);
            printf("\n");
            printf("Expected output: \t0x");
            for(i=0; i<aes_exp_res->output_size; ++i)
                printf("%02X",aes_exp_res->output[i]);
            printf("\n");
        }
        
    }
    
	return EXIT_SUCCESS;
}

void get_next_vector(FILE* file, AES_mode* mode, AES_crypt_type* crypt, AES_input* in, AES_res* exp_out, int* is_last_vector)
{
    char buf[MAXLINE_VEC];
    char val[VAL_MAX_SIZE_VEC];
    char id[ID_MAX_SIZE_VEC];
    int is_over = 0;//Set to 1 once te vector is over.
    
    while(fgets(buf, MAXLINE_VEC, file) && !is_over) {
        if(buf[0] != '#') {
            sscanf(buf, "%s = %s\n", id, val);
             printf("Next to parse: %s\n", id);
            if(strcmp(id, "mode") == 0) {
                *mode = ase_mode_strtoenum(val);
                 printf("mode set.\n");
            }
            else if(strcmp(id, "crypt") == 0) {
                *crypt = crypt_type_strtoenum(val);
                 printf("crypt set.\n");
            }
            else if(strcmp(id, "source") == 0) {
                in->source_size = strlen(val)/2;
                in->source = malloc(in->source_size);
                unhexify(in->source, val);
                 printf("source set.\n");
            }
            else if(strcmp(id, "aad") == 0) {
                in->aad_size = strlen(val)/2;
                in->aad = malloc(in->aad_size);
                unhexify(in->aad, val);
                 printf("aad set.\n");
            }
            else if(strcmp(id, "key") == 0) {
                in->key_size = strlen(val)/2;
                in->key = malloc(in->key_size);
                unhexify(in->key, val);
                 printf("key set.\n");
            }
            else if(strcmp(id, "iv") == 0) {
                in->iv_size = strlen(val)/2;
                in->iv = malloc(in->iv_size);
                unhexify(in->iv, val);
                 printf("iv set.\n");
            }
            else if(strcmp(id, "output") == 0) {
                printf("Parsing output.\n");
                exp_out->output_size = strlen(val)/2;
                printf("output_size set from test vector: %d.\n", exp_out->output_size);
                exp_out->output = malloc(exp_out->output_size);
                unhexify(exp_out->output, val);
                 printf("Output from test vector unhexified.\n");
                 printf("expected output set.\n");
            }
            else if(strcmp(id, "tag") == 0) {
                // could be shorten into exp_out->tag_size = unhexify(exp_out->tag, val);
                exp_out->tag_size = strlen(val)/2;
                exp_out->tag = malloc(exp_out->tag_size);
                unhexify(exp_out->tag, val);
                 printf("expected tag set.\n");
            }
            else if(strcmp(id, "END_VECTOR") == 0) {
                is_over = 1;
                if(strcmp(val, "LAST_VECTOR") == 0)
                    *is_last_vector = 1;
            }
        }
    }
}

AES_crypt_type crypt_type_strtoenum(const char* str)
{
    AES_crypt_type crypt;
    if(strcmp(str, "ENCRYPT") == 0)
        crypt = ENCRYPT;
    else if(strcmp(str, "DECRYPT") == 0)
        crypt = DECRYPT;
    return crypt;
}

AES_mode ase_mode_strtoenum(const char* str)
{
    AES_mode mode;
    if(strcmp(str, "AES_ECB") == 0)
        mode = AES_ECB;
    else if(strcmp(str, "AES_CBC") == 0)
        mode = AES_CBC;
    else if(strcmp(str, "AES_OFB") == 0)
        mode = AES_OFB;
    else if(strcmp(str, "AES_CTR") == 0)
        mode = AES_CTR;
    else if(strcmp(str, "AES_CFB") == 0)
        mode = AES_CFB;
    else if(strcmp(str, "AES_CMAC") == 0)
        mode = AES_CMAC;
    else if(strcmp(str, "AES_OMAC1") == 0)
        mode = AES_OMAC1;
    else if(strcmp(str, "AES_CCM") == 0)
        mode = AES_CCM;
    else if(strcmp(str, "AES_GCM") == 0)
        mode = AES_GCM;
    else if(strcmp(str, "AES_XTS") == 0)
        mode = AES_XTS;
    return mode;
}
