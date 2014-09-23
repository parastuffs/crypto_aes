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
#include "generic_tools.h"
 
//gcc -Wall aes_openssl.c -o aes_openssl -I../openssl-1.0.1i/include/ -lcrypto
//http://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption


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
    *tag_str = malloc(tag_size);
    omac_ctx ctx;
    omac_init(key, key_size, &ctx);
    omac_data(src_str, src_size, &ctx);
    omac_end(*tag_str, &ctx);
}

void aes_cmac(unsigned char* key, int key_size, unsigned char* src_str, int src_size, unsigned char** tag_str, int tag_size)
{
    *tag_str = malloc(tag_size);
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
    *dst_str = malloc(*dst_size);
	aes_context ctx;
    int status;
    
    // Use the same key schedule for both encryption and decryption
    // (cf PolarSSL documentation of aes_crypt_cfb8().
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
    int i;

    *dst_size = src_size;
    *dst_str = malloc(*dst_size);
    
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
    // printf("ECB context initialied alright.\n");
	*dst_size = src_size;
    // printf("Destination size set: %d.\n", *dst_size);
    // printf("Dest size address: %016X.\n", dst_size);
    *dst_str = calloc(*dst_size, sizeof(unsigned char));
    // printf("Destination string malloc'd.\n");
    
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

	*tag_str = malloc(tag_len * sizeof(unsigned char));
    memset(*tag_str, 0x00, tag_len);
    *output_size = src_size;
    *output = malloc(*output_size * sizeof(unsigned char));
    memset(*output, 0x00, *output_size);

	if(crypt == ENCRYPT)
		status = ccm_encrypt_and_tag( &ctx, src_size, iv_str, iv_size, aad_str, aad_size, src_str, *output, *tag_str, tag_len);
	else if(crypt == DECRYPT)
		status = ccm_auth_decrypt( &ctx, src_size, iv_str, iv_size, aad_str, aad_size, src_str, *output, *tag_str, tag_len);
	
	if(status != 0)
		polarssl_handleErrors(status, "CCM error.\n");
}

void aes_gcm(AES_crypt_type crypt, unsigned char* key_str, int key_size, unsigned char* iv_str, int iv_size, unsigned char* src_str, int src_size, unsigned char* aad_str, int aad_size, int tag_len, unsigned char** tag_str, unsigned char** output, int* output_size)
{
	gcm_context gcm;
    int status;
    int i;
    *tag_str = calloc(tag_len, sizeof(unsigned char));
    // memset(*tag_str, 0x00, tag_len);
    //TODO replace with calloc
    *output_size = src_size;
    *output = calloc(*output_size, sizeof(unsigned char));
    // memset(*output, 0x00, *output_size);

    if((status = gcm_init(&gcm, POLARSSL_CIPHER_ID_AES, key_str, key_size*8)) != 0)
		polarssl_handleErrors(status, "AES GCM init error.\n");
    if(crypt == ENCRYPT)
        status = gcm_crypt_and_tag(&gcm, GCM_ENCRYPT, src_size, iv_str, iv_size, aad_str, aad_size, src_str, *output, tag_len, *tag_str);
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

/*
int main(void)
{
    int i;
    
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    
    AES_MODE mode;
    
    // ------------------
    // OFB 128
    // ------------------
    mode = AES_OFB_128;
    
    int aes_ofb_key_size = 16;
    unsigned char *aes_ofb_key_128 = malloc(aes_ofb_key_size);
    unhexify(aes_ofb_key_128, "2b7e151628aed2a6abf7158809cf4f3c");
    
    int aes_ofb_ref_iv_1_size = 16;
    unsigned char *aes_ofb_ref_iv_1 = malloc(aes_ofb_ref_iv_1_size);
    unhexify(aes_ofb_ref_iv_1, "000102030405060708090A0B0C0D0E0F");

    int aes_ofb_ref_src_1_size = 16;
    unsigned char *aes_ofb_ref_src_1 = malloc(aes_ofb_ref_src_1_size);
    unhexify(aes_ofb_ref_src_1, "6bc1bee22e409f96e93d7e117393172a");

    unsigned char *aes_ofb_ref_ct_1;
    aes_ofb_ref_ct_1 = malloc(aes_ofb_ref_src_1_size);
    // unsigned char *decryptedtext;

    int ciphertext_len;
    ciphertext_len = openssl_encrypt(mode, aes_ofb_ref_src_1, aes_ofb_ref_src_1_size, aes_ofb_key_128, aes_ofb_ref_iv_1, aes_ofb_ref_ct_1);
    
    
    // ---------------
    // XTS 128
    // ---------------
    // Reference vectors: "format tweak value input - 128 hex str/XTSGenAES128.rsp" from http://csrc.nist.gov/groups/STM/cavp/documents/aes/XTSTestVectors.zip
    
    mode = AES_XTS_128;
    
    int aes_xts_key_size_128 = 32; // In XTS mode, keys are twice as long.
    unsigned char *aes_xts_key_128 = malloc(aes_xts_key_size_128);
    unhexify(aes_xts_key_128, "a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f");
    
    int aes_xts_ref_iv_1_size = 16;
    unsigned char *aes_xts_ref_iv_1 = malloc(aes_xts_ref_iv_1_size);
    unhexify(aes_xts_ref_iv_1, "4faef7117cda59c66e4b92013e768ad5");

    int aes_xts_ref_src_1_size = 16;
    unsigned char *aes_xts_ref_src_1 = malloc(aes_xts_ref_src_1_size);
    unhexify(aes_xts_ref_src_1, "ebabce95b14d3c8d6fb350390790311c");

    unsigned char *aes_xts_ref_ct_1;
    aes_xts_ref_ct_1 = malloc(aes_xts_ref_src_1_size);

    ciphertext_len = openssl_encrypt(mode, aes_xts_ref_src_1, aes_xts_ref_src_1_size, aes_xts_key_128, aes_xts_ref_iv_1, aes_xts_ref_ct_1);
    
    
    
    // ---------------
    // XTS 256
    // ---------------
    // Reference vectors: "format tweak value input - 128 hex str/XTSGenAES256.rsp" from http://csrc.nist.gov/groups/STM/cavp/documents/aes/XTSTestVectors.zip
    
    mode = AES_XTS_256;
    
    int aes_xts_key_size_256 = 64; // In XTS mode, keys are twice as long.
    unsigned char *aes_xts_key_256 = malloc(aes_xts_key_size_256);
    unhexify(aes_xts_key_256, "1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7cd6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08");
    
    int aes_xts_ref_iv_2_size = 16;
    unsigned char *aes_xts_ref_iv_2 = malloc(aes_xts_ref_iv_2_size);
    unhexify(aes_xts_ref_iv_2, "adf8d92627464ad2f0428e84a9f87564");

    int aes_xts_ref_src_2_size = 32;
    unsigned char *aes_xts_ref_src_2 = malloc(aes_xts_ref_src_2_size);
    unhexify(aes_xts_ref_src_2, "2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e");

    unsigned char *aes_xts_ref_ct_2;
    aes_xts_ref_ct_2 = malloc(aes_xts_ref_src_2_size);

    ciphertext_len = openssl_encrypt(mode, aes_xts_ref_src_2, aes_xts_ref_src_2_size, aes_xts_key_256, aes_xts_ref_iv_2, aes_xts_ref_ct_2);
    
    // ---------------
    // OMAC
    // ---------------
    // Test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/omac/omac-ad.pdf
    int aes_omac_tag_size = 16;
    
    int aes_omac_ref_key_128_size = 16;
    unsigned char* aes_omac_ref_key_128 = malloc(aes_omac_ref_key_128_size);
    unhexify(aes_omac_ref_key_128, "2b7e151628aed2a6abf7158809cf4f3c");
    
    int aes_omac_ref_msg_0_size = 0;
    unsigned char* aes_omac_ref_msg_0 = malloc(aes_omac_ref_msg_0_size);
    unhexify(aes_omac_ref_msg_0, "");
    
    unsigned char *aes_omac_k128_m0_tag = malloc(aes_omac_tag_size);
    
    aes_omac(aes_omac_ref_key_128, aes_omac_ref_key_128_size, aes_omac_ref_msg_0, aes_omac_ref_msg_0_size, aes_omac_k128_m0_tag, aes_omac_tag_size);
    
    printf("AES-OMAC1(k128, m0): 0x");
    for(i=0; i<aes_omac_tag_size; ++i)
        printf("%02X",aes_omac_k128_m0_tag[i]);
    printf("\n");
    
    // ---------------
    
    int aes_omac_ref_msg_16_size = 16;
    unsigned char* aes_omac_ref_msg_16 = malloc(aes_omac_ref_msg_16_size);
    unhexify(aes_omac_ref_msg_16, "6bc1bee22e409f96e93d7e117393172a");
    
    unsigned char *aes_omac_k128_m16_tag = malloc(aes_omac_tag_size);
    
    aes_omac(aes_omac_ref_key_128, aes_omac_ref_key_128_size, aes_omac_ref_msg_16, aes_omac_ref_msg_16_size, aes_omac_k128_m16_tag, aes_omac_tag_size);
    
    printf("AES-OMAC1(k128, m16): 0x");
    for(i=0; i<aes_omac_tag_size; ++i)
        printf("%02X",aes_omac_k128_m16_tag[i]);
    printf("\n");
    // ---------------
    int aes_omac_ref_msg_40_size = 40;
    unsigned char* aes_omac_ref_msg_40 = malloc(aes_omac_ref_msg_40_size);
    unhexify(aes_omac_ref_msg_40, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
    
    unsigned char *aes_omac_k128_m40_tag = malloc(aes_omac_tag_size);
    
    aes_omac(aes_omac_ref_key_128, aes_omac_ref_key_128_size, aes_omac_ref_msg_40, aes_omac_ref_msg_40_size, aes_omac_k128_m40_tag, aes_omac_tag_size);
    
    printf("AES-OMAC1(k128, m40): 0x");
    for(i=0; i<aes_omac_tag_size; ++i)
        printf("%02X",aes_omac_k128_m40_tag[i]);
    printf("\n");
    // ---------------
    int aes_omac_ref_msg_64_size = 64;
    unsigned char* aes_omac_ref_msg_64 = malloc(aes_omac_ref_msg_64_size);
    unhexify(aes_omac_ref_msg_64, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    
    unsigned char *aes_omac_k128_m64_tag = malloc(aes_omac_tag_size);
    
    aes_omac(aes_omac_ref_key_128, aes_omac_ref_key_128_size, aes_omac_ref_msg_64, aes_omac_ref_msg_64_size, aes_omac_k128_m64_tag, aes_omac_tag_size);
    
    printf("AES-OMAC1(k128, m64): 0x");
    for(i=0; i<aes_omac_tag_size; ++i)
        printf("%02X",aes_omac_k128_m64_tag[i]);
    printf("\n");
    
    
    // ---------------------------
    // CMAC
    // ---------------------------
    int aes_cmac_tag_size = 16;
    
    // Test vectors from CMACGenAES128.rsp, from http://csrc.nist.gov/groups/STM/cavp/documents/mac/cmactestvectors.zip
    // Vector #6
    int aes_cmac_ref_key_128_size = 16;
    unsigned char* aes_cmac_ref_key_128 = malloc(aes_cmac_ref_key_128_size);
    unhexify(aes_cmac_ref_key_128, "2b7e151628aed2a6abf7158809cf4f3c");
    
    int aes_cmac_ref_k128_msg_32_size = 16;
    unsigned char* aes_cmac_ref_k128_msg_16 = malloc(aes_cmac_ref_k128_msg_32_size);
    unhexify(aes_cmac_ref_k128_msg_16, "6bc1bee22e409f96e93d7e117393172a");
    
    unsigned char* aes_cmac_k128_m64_tag = malloc(aes_cmac_tag_size);
    
    aes_cmac(aes_cmac_ref_key_128, aes_cmac_ref_key_128_size, aes_cmac_ref_k128_msg_16, aes_cmac_ref_k128_msg_32_size, aes_cmac_k128_m64_tag);
    
    printf("AES-CMAC(k128, m64): 0x");
    for(i=0; i<aes_cmac_tag_size; ++i)
        printf("%02X", aes_cmac_k128_m64_tag[i]);
    printf("\n");

    // printf("Ciphertext is:\n");
    // BIO_dump_fp(stdout, ciphertext, ciphertext_len);

    // decryptedtext_len = openssl_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    // decryptedtext[decryptedtext_len] = '\0';

    // printf("Decrypted text is:\n");
    // printf("%s\n", decryptedtext);

    EVP_cleanup();
    ERR_free_strings();

    return EXIT_SUCCESS;
}
*/
