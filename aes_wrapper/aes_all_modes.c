#include <stdio.h>
#include <stdlib.h>

#include <polarssl/aes.h>
#include <polarssl/gcm.h>
#include <polarssl/error.h>
#include <polarssl/ccm.h>
 
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "aes_gladman/omac.h"
#include "aes_gladman/cmac.h"

#include "aes_all_modes.h"


void openssl_handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void polarssl_handleErrors(int status, const char* msg_str)
{
    if(msg_str != NULL)
        fprintf(stderr, "%s", msg_str);

    char err[1024];
    polarssl_strerror(status, err, 1024);
    printf("%s\n", err);
}

// Wrapper

void aes_wrapper(AES_mode mode, AES_crypt_type crypt, const AES_input* in, AES_res* res)
{
    switch(mode) {
        case AES_ECB:
            aes_ecb(crypt, in->key, in->key_size, in->source, in->source_size, &(res->output), &(res->output_size));
            break;
        case AES_CBC:
            aes_cbc(crypt, in->key, in->key_size, in->iv, in->source, in->source_size, &(res->output), &(res->output_size));
            break;
        case AES_OFB:
            aes_ofb(crypt, in->key, in->key_size, in->iv, in->source, in->source_size, &(res->output), &(res->output_size));
            break;
        case AES_CTR:
            aes_ctr(in->key, in->key_size, in->iv, in->source, in->source_size, &(res->output), &(res->output_size));
            break;
        case AES_CFB:
            aes_cfb(crypt, in->key, in->key_size, in->iv, in->source, in->source_size, &(res->output), &(res->output_size));
            break;
        case AES_CMAC:
            aes_cmac(in->key, in->key_size, in->source, in->source_size, &(res->tag), res->tag_size);
            break;
        case AES_OMAC1:
            aes_omac(in->key, in->key_size, in->source, in->source_size, &(res->tag), res->tag_size);
            break;
        case AES_CCM:
            aes_ccm(crypt, in->key, in->key_size, in->iv, in->iv_size, in->source, in->source_size, in->aad, in->aad_size, res->tag_size, &(res->tag), &(res->output), &(res->output_size));
            break;
        case AES_GCM:
            aes_gcm(crypt, in->key, in->key_size, in->iv, in->iv_size, in->source, in->source_size, in->aad, in->aad_size, res->tag_size, &(res->tag), &(res->output), &(res->output_size));
            break;
        case AES_XTS:
            aes_xts(crypt, in->key, in->key_size, in->iv, in->source, in->source_size, &(res->output), &(res->output_size));
            break;
        default:
            break;
    }
}




// Modes

void aes_xts(AES_crypt_type crypt, unsigned char* key, int key_size, unsigned char* iv, unsigned char* src, int src_size, unsigned char** output, int* output_size)
{
    EVP_CIPHER_CTX *ctx;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        openssl_handleErrors();

    if(crypt == ENCRYPT) {
        if(key_size*8 == 256) {
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, iv))
                openssl_handleErrors();
        }
        else if(key_size*8 == 512) {
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv))
                openssl_handleErrors();
        }
        if(1 != EVP_EncryptUpdate(ctx, *output, output_size, src, src_size))
            openssl_handleErrors();
    }
    else if(crypt == DECRYPT) {
        if(key_size*8 == 256) {
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, iv))
                openssl_handleErrors();
        }
        else if(key_size*8 == 512) {
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv))
                openssl_handleErrors();
        }
        if(1 != EVP_DecryptUpdate(ctx, *output, output_size, src, src_size))
            openssl_handleErrors();
    }
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void aes_ofb(AES_crypt_type crypt, unsigned char* key, int key_size, unsigned char* iv, unsigned char* src, int src_size, unsigned char** output, int* output_size)
{
    EVP_CIPHER_CTX *ctx;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        openssl_handleErrors();

    if(crypt == ENCRYPT) {
        if(key_size*8 == 128) {
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv))
                openssl_handleErrors();
        }
        else if(key_size*8 == 192) {
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_ofb(), NULL, key, iv))
                openssl_handleErrors();
        }
        else if(key_size*8 == 256) {
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv))
                openssl_handleErrors();
        }
        if(1 != EVP_EncryptUpdate(ctx, *output, output_size, src, src_size))
            openssl_handleErrors();
    }
    else if(crypt == DECRYPT) {
        if(key_size*8 == 128) {
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv))
                openssl_handleErrors();
        }
        else if(key_size*8 == 192) {
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_ofb(), NULL, key, iv))
                openssl_handleErrors();
        }
        else if(key_size*8 == 256) {
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv))
                openssl_handleErrors();
        }
        if(1 != EVP_DecryptUpdate(ctx, *output, output_size, src, src_size))
            openssl_handleErrors();
    }
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void aes_omac(unsigned char* key, int key_size, unsigned char* src_str, int src_size, unsigned char** tag_str, int tag_size)
{
    *tag_str = calloc(tag_size, sizeof(unsigned char));
    omac_ctx ctx;
    omac_init(key, key_size, &ctx);
    omac_data(src_str, src_size, &ctx);
    omac_end(*tag_str, &ctx);
}

void aes_cmac(unsigned char* key, int key_size, unsigned char* src_str, int src_size, unsigned char** tag_str, int tag_size)
{
    *tag_str = calloc(tag_size, sizeof(unsigned char));
    cmac_ctx ctx;
    cmac_init(key, key_size, &ctx);
    cmac_data(src_str, src_size, &ctx);
    cmac_end(*tag_str, &ctx);
}

void aes_ctr(unsigned char* key_str, int key_size, unsigned char* nc_str, unsigned char* src_str, int src_size, unsigned char** dst_str, int* dst_size)
{
	size_t nc_offset = 0;
	unsigned char stream_block[16];
	*dst_size = src_size;
    *dst_str = calloc(*dst_size, sizeof(unsigned char));
	aes_context ctx;
    int status;
    
    // Use the same key schedule for both encryption and decryption
    // (cf PolarSSL documentation of aes_crypt_cfb128().
	if((status = aes_setkey_enc(&ctx, key_str, key_size*8)) != 0)
		polarssl_handleErrors(status, "CTR init error.\n");
    
	if((status = aes_crypt_ctr(&ctx, src_size, &nc_offset, nc_str, stream_block, src_str, *dst_str)) != 0)
		polarssl_handleErrors(status, "CTR crypt error.\n");
}

void aes_cbc(AES_crypt_type crypt, unsigned char* key_str, int key_size, unsigned char* iv_str, unsigned char* src_str, int src_size, unsigned char** dst_str, int* dst_size)
{
	aes_context ctx;
	aes_init(&ctx);
    int status;

    *dst_size = src_size;
    *dst_str = calloc(*dst_size, sizeof(unsigned char));
    
    // There is no need to loop to process all the blocks, it's done automatically by the library.
    
    if(crypt == ENCRYPT) {
        if((status = aes_setkey_enc(&ctx, key_str, key_size*8)) != 0)
            polarssl_handleErrors(status, "CBC init error.\n");
        if((status = aes_crypt_cbc(&ctx, AES_ENCRYPT, src_size, iv_str, src_str, *dst_str)) != 0)
            polarssl_handleErrors(status, "CBC crypt error.\n");
    }
    else if(crypt == DECRYPT) {
        if((status = aes_setkey_dec(&ctx, key_str, key_size*8)) != 0)
            polarssl_handleErrors(status, "CBC init error.\n");
        if((status = aes_crypt_cbc(&ctx, AES_DECRYPT, src_size, iv_str, src_str, *dst_str)) != 0)
            polarssl_handleErrors(status, "CBC crypt error.\n");
    }
}

void aes_cfb(AES_crypt_type crypt, unsigned char* key_str, int key_size, unsigned char* iv_str, unsigned char* src_str, int src_size, unsigned char** dst_str, int* dst_size)
{
	aes_context ctx;
	aes_init(&ctx);
    int status;
    size_t iv_offset = 0;
    
	*dst_size = src_size;
    *dst_str = calloc(*dst_size, sizeof(unsigned char));

    // Use the same key schedule for both encryption and decryption
    // (cf PolarSSL documentation of aes_crypt_cfb128().
	if((status = aes_setkey_enc(&ctx, key_str, key_size*8)) != 0)
		polarssl_handleErrors(status, "CFB init error.\n");

    if(crypt == ENCRYPT) {
        if((status = aes_crypt_cfb128(&ctx, AES_ENCRYPT, src_size, &iv_offset, iv_str, src_str, *dst_str)) != 0)
            polarssl_handleErrors(status, "CFB init error.\n");
    }
    else if(crypt == DECRYPT) {
        if((status = aes_crypt_cfb128(&ctx, AES_DECRYPT, src_size, &iv_offset, iv_str, src_str, *dst_str)) != 0)
            polarssl_handleErrors(status, "CFB init error.\n");
    }
}

void aes_ecb(AES_crypt_type crypt, unsigned char* key_str, int key_size, unsigned char* src_str, int src_size, unsigned char** dst_str, int* dst_size)
{
    int i;
    int status;
    int block_size = 16;
    aes_context ctx;
	aes_init(&ctx);
	*dst_size = src_size;
    *dst_str = calloc(*dst_size, sizeof(unsigned char));
    
    // Per-block encryption/decryption. We expect to be fed with an full number of block (128 bits).
    if(crypt == ENCRYPT) {
        // printf("Let's encrypt that ECB.\n");
        if((status = aes_setkey_enc(&ctx, key_str, key_size*8)) != 0)
            polarssl_handleErrors(status, "ECB init error.\n");
        // printf("ecb polarssl init ok.\n");
        for(i=0; i<(*dst_size)/block_size; ++i) {
            if((status = aes_crypt_ecb(&ctx, AES_ENCRYPT, src_str+(i*block_size), *dst_str+(i*block_size))) != 0)
                polarssl_handleErrors(status, "ECB crypt error.\n");
        }
    }
    else if(crypt == DECRYPT) {
        if((status = aes_setkey_dec(&ctx, key_str, key_size*8)) != 0)
            polarssl_handleErrors(status, "ECB init error.\n");
            
        for(i=0; i<(*dst_size)/block_size; ++i) {
            if((status = aes_crypt_ecb(&ctx, AES_DECRYPT, src_str+(i*block_size), *dst_str+(i*block_size))) != 0)
                polarssl_handleErrors(status, "ECB crypt error.\n");
        }
    }
}

void aes_ccm(AES_crypt_type crypt, unsigned char* key_str, int key_size, unsigned char* iv_str, int iv_size, unsigned char* src_str, int src_size, unsigned char* aad_str, int aad_size, int tag_len, unsigned char** tag_str, unsigned char** output, int* output_size)
{
	ccm_context ctx;
	int status;
    
	if((status = ccm_init( &ctx, POLARSSL_CIPHER_ID_AES, key_str, key_size*8 )) != 0)
		polarssl_handleErrors(status, "CCM init error.\n");

    *output_size = src_size;
    *output = calloc(*output_size, sizeof(unsigned char));

	if(crypt == ENCRYPT) {
        *tag_str = calloc(tag_len, sizeof(unsigned char));
		status = ccm_encrypt_and_tag( &ctx, src_size, iv_str, iv_size, aad_str, aad_size, src_str, *output, *tag_str, tag_len);
    }
	else if(crypt == DECRYPT)
		status = ccm_auth_decrypt( &ctx, src_size, iv_str, iv_size, aad_str, aad_size, src_str, *output, *tag_str, tag_len);
	
	if(status != 0)
		polarssl_handleErrors(status, "CCM error.\n");
}

void aes_gcm(AES_crypt_type crypt, unsigned char* key_str, int key_size, unsigned char* iv_str, int iv_size, unsigned char* src_str, int src_size, unsigned char* aad_str, int aad_size, int tag_len, unsigned char** tag_str, unsigned char** output, int* output_size)
{
	gcm_context gcm;
    int status;
    *output_size = src_size;
    *output = calloc(*output_size, sizeof(unsigned char));

    if((status = gcm_init(&gcm, POLARSSL_CIPHER_ID_AES, key_str, key_size*8)) != 0)
		polarssl_handleErrors(status, "AES GCM init error.\n");
    if(crypt == ENCRYPT){
        *tag_str = calloc(tag_len, sizeof(unsigned char)); // No need to malloc the tag in decryption mode, since the tag is already filled.
        status = gcm_crypt_and_tag(&gcm, GCM_ENCRYPT, src_size, iv_str, iv_size, aad_str, aad_size, src_str, *output, tag_len, *tag_str);
    }
    else if(crypt == DECRYPT)
        status = gcm_auth_decrypt(&gcm, src_size, iv_str, iv_size, aad_str, aad_size, *tag_str, tag_len, src_str, *output);

    if(status != 0)
		polarssl_handleErrors(status, "AES GCM encryption error.\n");
}

void init_aes_wrapper()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

AES_crypt_type crypt_type_strtoenum(const char* str)
{
    AES_crypt_type crypt;
    if(strcmp(str, "ENCRYPT") == 0)
        crypt = ENCRYPT;
    else if(strcmp(str, "DECRYPT") == 0)
        crypt = DECRYPT;
    else if(strcmp(str, "HASH") == 0)
        crypt = HASH;
    return crypt;
}

AES_mode aes_mode_strtoenum(const char* str)
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

char* aes_mode_enumtostr(AES_mode mode)
{
	if(mode == AES_ECB)
		return "AES ECB";
	if(mode == AES_CBC)
		return "AES CBC";
	if(mode == AES_OFB)
		return "AES OFB";
	if(mode == AES_CTR)
		return "AES CTR";
	if(mode == AES_CFB)
		return "AES CFB";
	if(mode == AES_CMAC)
		return "AES CMAC";
	if(mode == AES_OMAC1)
		return "AES OMAC1";
	if(mode == AES_CCM)
		return "AES CCM";
	if(mode == AES_GCM)
		return "AES GCM";
	if(mode == AES_XTS)
		return "AES XTS";
	else {
		return "mode unrecognized";
	}
}

char* crypt_type_enumtostr(AES_crypt_type crypt)
{
    if(crypt == ENCRYPT)
        return "ENCRYPT";
    else if(crypt == DECRYPT)
        return "DECRYPT";
    else if(crypt == HASH)
        return "HASH";
    else
        return "encryption type unrecognized";
}
