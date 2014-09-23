#ifndef AES_ALL_MODES_H
#define AES_ALL_MODES_H

typedef enum {
	ENCRYPT,
	DECRYPT,
    HASH
} AES_crypt_type;

typedef enum {
	AES_ECB,
	AES_CBC,
	AES_OFB,
	AES_CTR,
	AES_CFB,
	AES_CMAC,
	AES_OMAC1,
	AES_CCM,
	AES_GCM,
	AES_XTS
} AES_mode;

typedef struct {
	unsigned char*  tag;            ///< Data tag, optional.
	int             tag_size;       ///< Data tag size, in bytes
	unsigned char*  output;         ///< Secure data
	int             output_size;    ///< Secure data size, in bytes
} AES_res;

typedef struct {
	unsigned char*	source;			///< Source string to be encrypted or decrypted, depending on the mode.
	int				source_size;	///< Source string size, in bytes.
	unsigned char*	key;			///< Key string.
	int				key_size;		///< Key size, in bytes.
	unsigned char*	iv;				///< IV string.
	int				iv_size;		///< IV size, in bytes.
	unsigned char*	aad;			///< Additional data string, optional.
	int				aad_size;		///< Additional data size.
} AES_input;

// PolarSSL
/**
 * \brief polarssl error handler.
 * 
 * \param status	Status of the error, processed by PolarSSL API.
 * \param msg_str	Additional message to the error, null terminated.
 * 					No new line is appended in the function, you should
 *					set one in the message.
 */
void polarssl_handleErrors(int status, const char* msg_str);

// openssl
void openssl_handleErrors(void);

/**
 * \brief AES general wrapper method.
 * 
 * Switch on the \c mode and calls the corresponding function.
 * 
 * \param		mode	AES mode to use.
 * \param		crypt	Encryption or decryption.
 * \param[in]	in		Input structure. Depending on the mode, not all field need to be filled.
 * \param[out]	res		Output structure. Depending on the mode, not all fields will be filled.
 */
void aes_wrapper(AES_mode mode, AES_crypt_type crypt, const AES_input* in, AES_res* res);

// Modes invocation
/**
 * AES mode OMAC1.
 * 
 * Implementation of <a href="http://brgladman.org/oldsite/AES/">Brian Gladman</a>.
 * 
 * \param		key			Key string.
 * \param		key_size	Key size in bytes.
 *							Either 16, 24 or 32.
 * \param[in]	src_str		Source string.
 * \param		src_size	Source string size, in bytes.
 * \param[out]	tag_str		Pointer to the resulting tag string. Memory allocation is done in function.
 * \param[in]	tag_size	Tag size in bytes.
 */
void aes_omac(unsigned char* key, int key_size, unsigned char* src_str, int src_size, unsigned char** tag_str, int tag_size);

/**
 * AES mode CMAC.
 * 
 * Implementation of <a href="http://brgladman.org/oldsite/AES/">Brian Gladman</a>.
 * 
 * \param		key			Key string.
 * \param		key_size	Key size in bytes.
 *							Either 16, 24 or 32.
 * \param[in]	src_str		Source string.
 * \param		src_size	Source string size, in bytes.
 * \param[out]	tag_str		Pointer to the resulting tag string. Memory allocation is done in function.
 * \param[in]	tag_size	Tag size in bytes.
 *                          Supports any length of tag up to 16 bytes.
 *                          Tags smaller than 16 bytes are simply truncated.
 */
void aes_cmac(unsigned char* key, int key_size, unsigned char* src_str, int src_size, unsigned char** tag_str, int tag_size);

/**
 * AES mode GCM.
 * 
 * Library: PolarSSL
 * 
 * \param		crypt		ENCRYPT or DECRYPT
 * \param		key_str		Key string.
 * \param		key_size	Key size in bytes.
 *							Either 16 or 32.
 * \param		iv_str		IV string.
 * \param		iv_size		IV string size, in bytes (must be 96).
 * \param[in]	src_str		Source string.
 * \param		src_size	Source string size, in bytes.
 * \param		aad_str		Additional data string.
 * \param		aad_size	Additional data string size, in bytes.
 * \param[out]	tag_str		Pointer to the resulting tag string.
 * \param[in]	tag_len		Tag size in bytes (16).
 * \param[out]	output		Pointer to the resulting output.
 * \param[out]	output_size	Output size, in bytes. Set in the function.
 */
void aes_gcm(AES_crypt_type crypt, unsigned char* key_str, int key_size, unsigned char* iv_str, int iv_size, unsigned char* src_str, int src_size, unsigned char* aad_str, int aad_size, int tag_len, unsigned char** tag_str, unsigned char** output, int* output_size);

/**
 * AES mode CCM.
 * 
 * Library: PolarSSL
 * 
 * \param		crypt		ENCRYPT or DECRYPT
 * \param		key_str		Key string.
 * \param		key_size	Key size in bytes.
 *							Either 16, 24 or 32.
 * \param		iv_str		IV string.
 * \param		iv_size		IV string size, in bytes.
 * \param[in]	src_str		Source string.
 * \param		src_size	Source string size, in bytes.
 * \param		aad_str		Additional data string.
 * \param		aad_size	Additional data string size, in bytes.
 * \param[out]	tag_str		Pointer to the resulting tag string.
 * \param[in]	tag_len		Tag size in bytes.
 * \param[out]	output		Pointer to the resulting output.
 * \param[out]	output_size	Output size, in bytes. Set in the function.
 */
void aes_ccm(AES_crypt_type crypt, unsigned char* key_str, int key_size, unsigned char* iv_str, int iv_size, unsigned char* src_str, int src_size, unsigned char* aad_str, int aad_size, int tag_len, unsigned char** tag_str, unsigned char** output, int* output_size);

/**
 * \brief AES mode CBC.
 * 
 * Library: PolarSSL
 * 
 * \param		crypt		ENCRYPT or DECRYPT
 * \param		key_str		Key string.
 * \param		key_size	Key size in bytes.
 *							Either 16, 24 or 32.
 * \param[in]	iv_str		IV string, 128-bits long.
 * \param[in]	src_str		Source string.
 * \param		src_size	Source string size, in bytes.
 * \param[out]	dst_str		Poiter to the output string. No need to allocate memory.
 * \param[out]	dst_size	Output string size, in bytes. Set in the function.
 */
void aes_cbc(AES_crypt_type crypt, unsigned char* key_str, int key_size, unsigned char* iv_str, unsigned char* src_str, int src_size, unsigned char** dst_str, int* dst_size);

/**
 * \brief AES mode CFB.
 * 
 * Library: PolarSSL
 * 
 * \param		crypt		ENCRYPT or DECRYPT
 * \param		key_str		Key string.
 * \param		key_size	Key size in bytes.
 *							Either 16, 24 or 32.
 * \param[in]	iv_str		IV string, 128-bits long.
 * \param[in]	src_str		Source string.
 * \param		src_size	Source string size, in bytes.
 * \param[out]	dst_str		Pointer to the output string. No need to allocate memory.
 * \param[out]	dst_size	Output string size, in bytes. Set in the function.
 */
void aes_cfb(AES_crypt_type crypt, unsigned char* key_str, int key_size, unsigned char* iv_str, unsigned char* src_str, int src_size, unsigned char** dst_str, int* dst_size);

/**
 * AES mode ECB.
 * 
 * Library: openSSL
 * 
 * \param		mode		Encryption mode.
 * \param		key_str		Key string.
 * \param		key_size	Key size in bytes.
 *							Either 16, 24 or 32.
 * \param[in]	src_str		Plain text string to be encrypted or decrypted.
 * \param		src_size	Plain text size, in bytes.
 * \param[out]	dst_str		Pointer to the output string. Initialized in the function.
 * \param		dst_size	Pointer to the output string size, set in function.
 */
void aes_ecb(AES_crypt_type mode, unsigned char* key_str, int key_size, unsigned char* src_str, int src_size, unsigned char** dst_str, int* dst_size);

/**
 * \brief AES mode CTR.
 * 
 * Library: PolarSSL
 * 
 * If the input data is larger than one block (128 bits), the counter is automatically
 * incremented by PolarSSL.
 * 
 * There is no distinction between the encrypt and decrypt mode.
 * 
 * \param		key_str		Key string.
 * \param		key_size	Key size in bytes.
 *							Either 16, 24 or 32.
 * \param		nc_str		Nonce counter string, equivalent to the IV in other modes.
 * 							128-bits long.
 * \param[in]	src_str		Source string.
 * \param		src_size	Source string size, in bytes.
 * \param[out]	dst_str		Pointer to the output string. No need to allocate memory.
 * \param[out]	dst_size	Output string size, in bytes. Set in the function.
 */
void aes_ctr(unsigned char* key_str, int key_size, unsigned char* nc_str, unsigned char* src_str, int src_size, unsigned char** dst_str, int* dst_size);

/**
 * \brief AES mode OFB.
 * 
 * Library: openssl
 * 
 * \param		crypt		ENCRYPT or DECRYPT
 * \param		key			Key string.
 * \param		key_size	Key size in bytes.
 *							Either 16, 24 or 32.
 * \param[in]	iv			IV string, 128-bits long.
 * \param[in]	src			Source string.
 * \param		src_size	Source string size, in bytes.
 * \param[out]	output		Pointer to the output string. No need to allocate memory.
 * \param[out]	output_size	Output string size, in bytes. Set in the function.
 */
void aes_ofb(AES_crypt_type crypt, unsigned char* key, int key_size, unsigned char* iv, unsigned char* src, int src_size, unsigned char** output, int* output_size);

/**
 * \brief AES mode XTS.
 * 
 * Library: openssl
 * 
 * Note: bear in mind that in XTS mode, we use two keys. They are concatenated
 * in the \c key parameter, resulting in a parameter \c keysize twice as
 * big as the keysize of the mode.
 * 
 * \param		crypt		ENCRYPT or DECRYPT
 * \param		key			Key string.
 *							The two keys used by the mode should be concatenated.
 * \param		key_size	Key size in bytes.
 *							Either 64 (for 128-bits mode) or 128 (256-bits mode).
 * \param[in]	iv			IV string, 128-bits long.
 * \param[in]	src			Source string.
 * \param		src_size	Source string size, in bytes.
 * \param[out]	output		Output string. No need to allocate memory.
 * \param[out]	output_size	Output string size, in bytes. Set in the function.
 * 
 */
void aes_xts(AES_crypt_type crypt, unsigned char* key, int key_size, unsigned char* iv, unsigned char* src, int src_size, unsigned char** output, int* output_size);

/**
 * \brief Initialize aes wrapper.
 * 
 * Load everything needed by the different libraries used for the modes.
 * 
 */
void init_aes_wrapper(void);

/**
 * \brief Convert a string to the enum element it describes.
 * 
 * \param str   String to convert.
 *              Basically, it's the same name as the enum element, but as a string.
 */
AES_crypt_type crypt_type_strtoenum(const char* str);

/**
 * \brief Convert an AES_crypt_type element to a string.
 * 
 * \param crypt Element to convert.
 * 
 * \return The crypt type as a readable string, either ENCRYPT or DECRYPT.
 */
char* crypt_type_enumtostr(AES_crypt_type crypt);

/**
 * \brief Convert a string to the enum element it describes.
 * 
 * \param str   String to convert.
 *              Basically, it's the same name as the enum element, but as a string.
 */
AES_mode aes_mode_strtoenum(const char* str);

/**
 * \brief Convert an AES_mode element to a string.
 * 
 * \param mode  Element to convert.
 * 
 * \return The mode as a readable string. Not a complete sentence, just the mode.
 */
char* aes_mode_enumtostr(AES_mode mode);


#endif