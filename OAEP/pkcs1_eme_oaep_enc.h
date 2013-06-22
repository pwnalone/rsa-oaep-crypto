/**
 * File: pkcs1_eme_oaep_enc.h
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Defines the PKCS1_OAEP_Enc class which contains functions for padding
 *			messages using the OAEP padding scheme.
 */

#ifndef PKCS1_EME_OAEP_ENC_H
#define PKCS1_EME_OAEP_ENC_H

#include <iostream>
#include <string>
#include <gmpxx.h>
#include <stdint.h>

#include "../Data_Conv/data_conv_prims.h"
#include "../RSA/rsa_tb.h"
#include "../SHA256/sha256.h"
#include "../MGF1/pkcs1_mgf1.h"

/************************* class PKCS1_OAEP_Enc *************************
 *
 * PKCS1_OAEP_Enc(void);
 *		Postcondition: data variables are set to default values.
 *
 * PKCS1_OAEP_Enc(RSA_PubKey pkey);
 *		Precondition: pkey's key pair has been successfully initialized.
 *		Postcondition: data variables are set to default values, and m_k is
 *			set to length (in bytes) of pkey's public modulus.
 *
 * PKCS1_OAEP_Enc(RSA_PubKey pkey, uint8_t *M, size_t mLen,
 *				  uint8_t *L = NULL, size_t lLen = 0);
 *		Precondition: pkey's key pair has been successfully initialized, M
 *			has at least mLen uint8_t values in memory, and mLen satisfies this
 *			equation: mLen < k - 2*hLen - 2, where k is the length of the key
 *			and hLen is the length of the hash algorithm digest.
 *		Postcondition: m_k is set to length (in bytes) of pkey's public modulus,
 *			m_M is set to value of M, as long as mLen is a valid length of M,
 *			and m_Hash is updated with the value of L (of length lLen).
 *
 * PKCS1_OAEP_Enc(RSA_PubKey pkey, std::string M, std::string L = "");
 *		Precondition: pkey's key pair has been successfully initialized, M
 *			satisfies this equation: mLen < k - 2*hLen - 2, where k is the
 *			length of the key, hLen is the length of the hash algorithm digest,
 *			and mLen is the length of the string M.
 *		Postcondition: m_k is set to length (in bytes) of pkey's public modulus,
 *			m_M is set to value of M, as long as length of M is valid, and m_Hash
 *			is updated with the value of L.
 *
 * int set_key_len(RSA_PubKey pkey);
 *		Precondition: pkey's key pair has been succesfully initialized.
 *		Postcondition: m_k is set to length (in bytes) of pkey's public modulus.
 *			If a message has already been encoded, then, after calling this
 *			function, one must call the encode function once more before being
 *			able to get the encoded message value. Returns 0 upon success, and
 *			1 upon failure.
 *
 * int set_msg(uint8_t *M, size_t mLen);
 *		Precondition: A valid key length must be set, M has at least mLen uint8_t
 *			values in memory, and mLen satisfies this equation:
 *			mLen < k - 2*hLen - 2, where k is the length of the key, and hLen is
 *			the length of the hash algorithm digest.
 *		Postcondition: m_M is assigned the value of M as long as mLen is a valid
 *			length of M. If a message has already been encoded, then, after
 *			calling this function, one must call the encode function once more
 *			before being able to get the encoded message value. Returns 0 upon
 *			success, and 1 upon failure.
 *
 * int set_msg(std::string M);
 *		Precondition: A valid key length must be set, and M satisfies this
 *			equation: mLen < k - 2*hLen - 2, where k is the length of the key,
 *			hLen is the length of the hash algorithm digest, and mLen is the
 *			length of M.
 *		Postcondition: m_M is assigned the value of M as long as M has a valid
 *			length. If a message has already been encoded, calling this
 *			function will do the same as the above set_msg function. Returns 0
 *			upon success, and 1 upon failure.
 *
 * void update_label(uint8_t *L, size_t lLen);
 *		Precondition: L has at least lLen uint8_t values in memory.
 *		Postcondition: m_Hash is updated with L (of length lLen). If a message
 *			has already been encoded, then, after calling this function, one
 *			must call the encode function once more before being able to get
 *			the encoded message value.
 *
 * void update_label(std::string L);
 *		Postcondition: m_Hash is updated with L. If a message has already been
 *			encoded, calling this function will do the same as the above
 *			update_label function.
 *
 * void reset_label(void);
 *		Postcondition: m_Hash is reset to its initial state.
 *
 * int encode(void);
 *		Precondition: A valid key length and a valid message should already
 *			be set.
 *		Postcondition: Message m_M is encoded using the EME-OAEP padding
 *			scheme, specified in RFC 3447. Returns 0 upon success, and 1 upon
 *			failure.
 *
 * void clear_scheme(void);
 *		Postcondition: Frees all allocated memory associated with the object,
 *			and resets all the data variables to their default values.
 *
 * size_t get_key_len(void) const;
 *		Precondition: A valid key length should already have been set.
 *		Postcondition: Returns the length of the RSA public key (modulus
 *			length). This is also the length of the encoded message.
 *
 * void get_msg(uint8_t *M) const;
 *		Precondition: A valid message should already have been set.
 *		Postcondition: The unencoded message will be copied into M.
 *
 * size_t get_msg_len(void) const;
 *		Precondition: Same as get_msg function (See get_msg function).
 *		Postcondition: Returns the length of the unencoded message.
 *
 * size_t get_hash_len(void) const;
 *		Postcondition: Returns the length of the digest for the hash
 *			algorithm being used (SHA-256).
 *
 * void get_enc_msg(uint8_t *EM) const;
 *		Precondition: The encode function must have successfully encoded
 *			message m_M, and none of the data variables can have been changed
 *			since the last call to the encode function. EM must have at least
 *			m_k (key length) bytes of memory available.
 *		Postcondition: Encoded message m_EM is copied into EM.
 *
 * void set_hash_state(SHA256_Hash &hash);
 *		Postcondition: The entire state of hash is copied into m_Hash.
 *
 ************************************************************************/

class PKCS1_OAEP_Enc
{
	friend class RSA_OAEP;

	public:
		PKCS1_OAEP_Enc(void);
		PKCS1_OAEP_Enc(RSA_PubKey pkey);
		PKCS1_OAEP_Enc(RSA_PubKey pkey, uint8_t *M, size_t mLen,
					   uint8_t *L = NULL, size_t lLen = 0);
		PKCS1_OAEP_Enc(RSA_PubKey pkey, std::string M, std::string L = "");

		int				set_key_len(RSA_PubKey pkey);

		int				set_msg(uint8_t *M, size_t mLen);
		int				set_msg(std::string M);

		void			update_label(uint8_t *L, size_t lLen);
		void			update_label(std::string L);
		void			reset_label(void);

		int				encode(void);
		
		void			clear_scheme(void);

		size_t			get_key_len(void) const;
		void			get_msg(uint8_t *M) const;
		size_t			get_msg_len(void) const;
		size_t			get_hash_len(void) const;

		void			get_enc_msg(uint8_t *EM) const;

	private:
		void			set_hash_state(SHA256_Hash &hash);

		uint8_t			*m_EM;		/* Encoded message */
		size_t			m_k;		/* RSA key length */
		
		uint8_t			*m_M;		/* Unencoded message */
		size_t			m_mLen;

		SHA256_Hash		m_Hash;
		size_t			m_hLen;

		bool			m_valid_key_len;
		bool			m_valid_msg_len;
		bool			m_enc_done;
};

#endif		/* PKCS1_EME_OAEP_ENC_H */
