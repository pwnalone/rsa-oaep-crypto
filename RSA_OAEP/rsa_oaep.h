/**
 * File: rsa_oaep.h
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Defines the RSA_OAEP class which contains functions for encrypting
 *			and decrypting messages using the OAEP padding scheme combined with
 *			the RSA encryption/decryption primitives.
 */

#ifndef RSA_OAEP_H
#define RSA_OAEP_H

#include <iostream>
#include <string>
#include <gmpxx.h>
#include <stdint.h>

#include "../Data_Conv/data_conv_prims.h"
#include "../RSA/rsa_tb.h"
#include "../SHA256/sha256.h"
#include "../OAEP/pkcs1_eme_oaep_enc.h"
#include "../OAEP/pkcs1_eme_oaep_dec.h"

/************************* class RSA_OAEP *************************
 *
 * RSA_OAEP(void);
 *		Postcondition: Object's data variables are set to their default values.
 *
 * RSA_OAEP(RSA_Primes ppair);
 *		Postcondition: Calls gen_keys function (See gen_keys function).
 *
 * RSA_OAEP(RSA_PubKey pub_k);
 *		Precondition: Same as set_pubkey function (See set_pubkey function).
 *		Postcondition: Calls set_pubkey function (See set_pubkey function).
 *
 * RSA_OAEP(RSA_PrivKey priv_k);
 *		Precondition: Same as set_privkey function (See set_privkey function).
 *		Postcondition: Calls set_privkey function (See set_privkey function).
 *
 * RSA_OAEP(RSA_PubKey pub_k, RSA_PrivKey priv_k);
 *		Precondition: Same as set_keys function (See set_keys function).
 *		Postcondition: Calls set_keys function (See set_keys function).
 *
 * void gen_keys(void);
 *		Postcondition: Generates an RSA public key and an RSA private key to be
 *			used for encryption and decryption.
 *
 * void gen_keys(RSA_Primes ppair);
 *		Postcondition: Generates an RSA public key and an RSA private key using
 *			ppair to be used for encryption and decryption.
 *
 * int set_pubkey(RSA_PubKey pub_k);
 *		Precondition: pub_k must be a valid RSA public key.
 *		Postcondition: Sets pub_k as the RSA public key used in encryption.
 *
 * int set_privkey(RSA_PrivKey priv_k);
 *		Precondition: priv_k must contain at least a valid RSA private key pair.
 *		Postcondition: Sets priv_k as the RSA private key used in decryption.
 *
 * int set_keys(RSA_PubKey pub_k, RSA_PrivKey priv_k);
 *		Precondition: pub_k must be a valid RSA public key, and priv_k must
 *			contain at least a valid RSA private key pair.
 *		Postcondition: Set pub_k as the RSA public key used in encryption, and
 *			priv_k as the RSA private key used in decryption.
 *
 * int set_msg(uint8_t *M, size_t mLen);
 *		Precondition: M should have at least mLen indices in memory, and M must
 *			be less than the modulus value when converted into an integer. RSA
 *			public key should already be set.
 *		Postcondition: M is set as the message to be encrypted. Returns 0 upon
 *			success, and 1 upon failure.
 *
 * int set_msg(std::string M);
 *		Precondition: M must be less than the modulus value when converted into
 *			an integer. RSA public key should already be set.
 *		Postcondition: M is set as the message to be encrypted. Returns 0 upon
 *			success, and one upon failure.
 *
 * int set_cipher(uint8_t *C, size_t cLen);
 *		Precondition: C should have at least cLen indices in memory. C must be
 *			an RSA-OAEP cipher, encrypted with the public key corresponding to
 *			the set private key. RSA private key should already be set.
 *		Postcondition: C is set as the cipher to be decrypted.
 *
 * int set_cipher(mpz_class C);
 *		Precondition: C must be an RSA-OAEP cipher, encrypted with the public
 *			key corresponding to the set private key. RSA private key should
 *			already be set.
 *		Postcondition: C is set as the cipher to be decrypted.
 *
 * void update_label(uint8_t *L, size_t lLen);
 *		Precondition: L must have at least lLen indices in memory.
 *		Postcondition: The label hash is updated with L, to be used for either
 *			the encryption or decryption process.
 *
 * void update_label(std::string L);
 *		Postcondition: The label hash is updated with L, to be used for either
 *			the encryption or decryption process.
 *
 * void reset_label(void);
 *		Postcondition: The label hash is reset to its initial state.
 *
 * int encrypt(uint8_t **C, size_t &cLen);
 *		Precondition: An RSA public key should be set, a message should be set,
 *			and an optional label should be set if one is being used.
 *		Postcondition: The message is padded using the EME-OAEP padding scheme
 *			and encrypted using the RSA encryption scheme. The resulting cipher
 *			is stored in *C and cLen is set to the length of the cipher. Returns
 *			0 upon success, and 1 upon failure.
 *
 * int encrypt(mpz_class &C);
 *		Precondition: An RSA public key should be set, a message should be set,
 *			and an optional label should be set if one is being used.
 *		Postcondition: The message is padded using the EME-OAEP padding scheme
 *			and encrypted using the RSA encryption scheme. The resulting cipher
 *			is stored in C. Returns 0 upon success, and 1 upon failure.
 *
 * int decrypt(uint8_t **M, size_t &mLen);
 *		Precondition: An RSA private key should be set, a cipher should be set,
 *			and the label associated with the encrypted message (cipher) should
 *			be set if one was used during the encryption process.
 *		Postcondition: The cipher is decrypted using the RSA decryption scheme,
 *			and then is decoded by reversing the OAEP padding scheme. If a
 *			message was successfully decrypted, then it is stored in M and mLen
 *			is set to the length of the message. Returns 0 upon success, and 1
 *			upon failure.
 *
 * int decrypt(mpz_class &M);
 *		Precondition: An RSA private key should be set, a cipher should be set,
 *			and the label associated with the encrypted message (cipher) should
 *			be set if one was using during the encryption process.
 *		Postcondition: The cipher is decrypted using the RSA decryption scheme,
 *			and then is decoded by reversing the OAEP padding scheme. If a
 *			message was successfully decrypted, then it is stored in M. Returns
 *			0 upon success, and 1 upon failure.
 *
 * void clear(void);
 *		Postcondition: Frees all memory associated with the object, and resets
 *			all data variables back to their default values.
 *
 * void get_pubkey(RSA_PubKey &pub_k);
 *		Precondition: An RSA public key should already be set.
 *		Postcondition: Copies the object's public key over to pub_k.
 *
 * void get_privkey(RSA_PrivKey &priv_k);
 *		Precondition: An RSA private key should already be set.
 *		Postcondition: Copies the object's private key over to priv_k.
 *
 * int copy_privkey(RSA_PrivKey &cpy, RSA_PrivKey pkey);
 *		Precondition: pkey must contain at least a valid RSA private key pair.
 *		Postcondition: Copies pkey over to cpy. Returns 0 upon success, and 1
 *			upon failure.
 *
 ******************************************************************/

class RSA_OAEP
{
	public:
		RSA_OAEP(void);
		RSA_OAEP(RSA_Primes ppair);
		RSA_OAEP(RSA_PubKey pub_k);
		RSA_OAEP(RSA_PrivKey priv_k);
		RSA_OAEP(RSA_PubKey pub_k, RSA_PrivKey priv_k);

		void				gen_keys(void);
		void				gen_keys(RSA_Primes ppair);

		int					set_pubkey(RSA_PubKey pub_k);
		int					set_privkey(RSA_PrivKey priv_k);
		int					set_keys(RSA_PubKey pub_k, RSA_PrivKey priv_k);

		int					set_msg(uint8_t *M, size_t mLen);
		int					set_msg(std::string M);

		int					set_cipher(uint8_t *C, size_t cLen);
		int					set_cipher(mpz_class C);

		void				update_label(uint8_t *L, size_t lLen);
		void				update_label(std::string L);
		void				reset_label(void);

		int					encrypt(uint8_t **C, size_t &cLen);
		int					encrypt(mpz_class &C);

		int					decrypt(uint8_t **M, size_t &mLen);
		int					decrypt(mpz_class &M);

		void				clear(void);

		void				get_pubkey(RSA_PubKey &pub_k);
		void				get_privkey(RSA_PrivKey &priv_k);

	private:
		int					copy_privkey(RSA_PrivKey &cpy, RSA_PrivKey pkey);

		mpz_class			m_C;

		RSA_PubKey			m_pub_key;
		RSA_PrivKey			m_priv_key;

		PKCS1_OAEP_Enc		m_enc_scheme;
		PKCS1_OAEP_Dec		m_dec_scheme;

		SHA256_Hash			m_Hash;

		bool				m_pub_key_set;
		bool				m_priv_key_set;
		bool				m_cipher_set;
};

#endif			/* RSA_OAEP_H */
