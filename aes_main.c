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

int main(int argc, char** argv)
{
    init_aes_wrapper();
    
    int i;
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
        int fail;
        while(!is_last_vector) {
            get_next_vector(fp, &mode, &crypt, aes_in, aes_exp_res, &is_last_vector);
            printf("\n======== %s - KEY %d - %s =========\n", aes_mode_enumtostr(mode), aes_in->key_size * 8, crypt_type_enumtostr(crypt));
            printf("Source(%d): \t\t0x", aes_in->source_size);
            for(i=0; i<aes_in->source_size; ++i)
                printf("%02X", aes_in->source[i]);
            printf("\n");
            printf("key(%d): \t\t0x", aes_in->key_size);
            for(i=0; i<aes_in->key_size; ++i)
                printf("%02X", aes_in->key[i]);
            printf("\n");
            aes_res->tag_size = aes_exp_res->tag_size;
            aes_wrapper(mode, crypt, aes_in, aes_res);
            if(mode == AES_ECB || mode == AES_CBC ||
                mode == AES_OFB || mode == AES_CTR || 
                mode == AES_CFB || mode == AES_CCM || 
                mode == AES_GCM || mode == AES_XTS) {
				fail = 0;
                printf("Output: \t\t0x");
                for(i=0; i<aes_res->output_size; ++i)
                    printf("%02X",aes_res->output[i]);
                printf("\n");
                printf("Expected output: \t0x");
                for(i=0; i<aes_exp_res->output_size; ++i) {
                    printf("%02X",aes_exp_res->output[i]);
                    if(aes_exp_res->output[i] != aes_res->output[i])
						fail = 1;
				}
                printf("\n");
                printf("%s\n",fail?"<< FAIL":">> SUCCESS");
            }
            if(mode == AES_CMAC || mode == AES_OMAC1 ||
                mode == AES_CCM || mode == AES_GCM) {
				fail = 0;
                printf("Tag: \t\t0x");
                for(i=0; i<aes_res->tag_size; ++i)
                    printf("%02X",aes_res->tag[i]);
                printf("\n");
                printf("Expected tag: \t0x");
                for(i=0; i<aes_exp_res->tag_size; ++i) {
                    printf("%02X",aes_exp_res->tag[i]);
                    if(aes_exp_res->tag[i] != aes_res->tag[i])
						fail = 1;
				}
                printf("\n");
                printf("%s\n",fail?"<< FAIL":">> SUCCESS");
            }
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
             //printf("Next to parse: %s\n", id);
            if(strcmp(id, "mode") == 0) {
                *mode = aes_mode_strtoenum(val);
                 //printf("mode set.\n");
            }
            else if(strcmp(id, "crypt") == 0) {
                *crypt = crypt_type_strtoenum(val);
                 //printf("crypt set.\n");
            }
            else if(strcmp(id, "source") == 0) {
                in->source_size = strlen(val)/2;
                in->source = malloc(in->source_size);
                unhexify(in->source, val);
                 //printf("source set.\n");
            }
            else if(strcmp(id, "aad") == 0) {
                in->aad_size = strlen(val)/2;
                in->aad = malloc(in->aad_size);
                unhexify(in->aad, val);
                 //printf("aad set.\n");
            }
            else if(strcmp(id, "key") == 0) {
                in->key_size = strlen(val)/2;
                in->key = malloc(in->key_size);
                unhexify(in->key, val);
                 //printf("key set.\n");
            }
            else if(strcmp(id, "iv") == 0) {
                in->iv_size = strlen(val)/2;
                in->iv = malloc(in->iv_size);
                unhexify(in->iv, val);
                 //printf("iv set.\n");
            }
            else if(strcmp(id, "output") == 0) {
                //printf("Parsing output.\n");
                exp_out->output_size = strlen(val)/2;
                //printf("output_size set from test vector: %d.\n", exp_out->output_size);
                exp_out->output = malloc(exp_out->output_size);
                unhexify(exp_out->output, val);
                 //printf("Output from test vector unhexified.\n");
                 //printf("expected output set.\n");
            }
            else if(strcmp(id, "tag") == 0) {
                // could be shorten into exp_out->tag_size = unhexify(exp_out->tag, val);
                exp_out->tag_size = strlen(val)/2;
                exp_out->tag = malloc(exp_out->tag_size);
                unhexify(exp_out->tag, val);
                 //printf("expected tag set.\n");
            }
            else if(strcmp(id, "END_VECTOR") == 0) {
                is_over = 1;
                if(strcmp(val, "LAST_VECTOR") == 0)
                    *is_last_vector = 1;
            }
        }
    }
}
