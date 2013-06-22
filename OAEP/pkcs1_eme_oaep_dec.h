/**
 * File: pkcs1_eme_oaep_dec.h
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Defines the PKCS1_OAEP_Dec class which contains functions for reversing
 *			the OAEP padding scheme and retrieving a padded message.
 *		- Follows the OAEP algorithm documented in RFC 3447 so as to prevent against
 *			timing attacks.
 */

#ifndef PKCS1_EME_OAEP_DEC_H
#define PKCS1_EME_OAEP_DEC_H

#include <string>
#include <gmpxx.h>
#include <stdint.h>

#include "../Data_Conv/data_conv_prims.h"
#include "../RSA/rsa_tb.h"
#include "../SHA256/sha256.h"
#include "../MGF1/pkcs1_mgf1.h"

/************************* class PKCS1_OAEP_Dec *************************
 *
 * PKCS1_OAEP_Dec(void);
 *		Postcondition: Data variables of object are set to default values.
 *
 * PKCS1_OAEP_Dec(RSA_PrivKey pkey);
 *		Precondition: pkey is already initialized with a valid private key.
 *		Postcondition: The key length data variable is set to the length of
 *			pkey's modulus, and all other data variables are set to their
 *			defaults.
 *
 * PKCS1_OAEP_Dec(RSA_PrivKey pkey, uint8_t *EM, size_t EM_len,
 *				  uint8_t *L = NULL, size_t lLen = 0);
 *		Precondition: pkey is already initialized with a valid private key,
 *			and EM has at least EM_len indices in memory. EM_len must be
 *			equal to the length of the key. If L is specified, then lLen
 *			should correspond to the length of L. L should hold the value of
 *			the label associated with the encoded message to decode.
 *		Postcondition: The key length is set using pkey. Memory is allocated
 *			for encoded message variable and set with EM_len values of EM.
 *			If L is specified, then it is used to update the hash value of L.
 *
 * int set_key_len(RSA_PrivKey pkey);
 *		Precondition: pkey is already initialized with a valid private key.
 *		Postcondition: The key length data variable is set to the length of
 *			pkey's modulus. Calling this function requires one to set the
 *			encoded message value again before decoding. Returns 0 upon
 *			success, and 1 upon failure.
 *
 * int set_enc_msg(uint8_t *EM, size_t EM_len);
 *		Precondition: EM must have at least EM_len bytes in memory, and it
 *			must be an EME-OAEP-encoded message. A valid key length must
 *			also be set, and EM_len must be equal in value.
 *		Postcondition: Memory is allocated for an encoded message, and EM_len
 *			values from EM are copied to it.
 *
 * void update_label(uint8_t *L, size_t lLen);
 *		Precondition: L must have at least lLen indices in memory, and must
 *			be the label associated with the encoded message.
 *		Postcondition: L is used to update the label hash value.
 *
 * void update_label(std::string L);
 *		Precondition: L must be the label associated with the encoded message.
 *		Postcondition: Same as above update_label function.
 *
 * void reset_label(void);
 *		Postcondition: Reset the hash of the label L.
 *
 * int decode(void);
 *		Precondition: A valid key length must be set, and an EME-OAEP-encoded
 *			message of the same length must also be set. If the encoded
 *			message has a label associated with it, then that also must be
 *			supplied.
 *		Postcondition: The encoded message is decoded using the EME-OAEP
 *			decoding algorithm. Memory is allocated for the decoded message
 *			and the message is copied into the memory. Decoding errors are
 *			held off until the end to prevent against a timing attack. If
 *			errors did occurr, then the memory for the message is deallocated.
 *			Returns 0 upon success, 1 if no key length or encoded message were
 *			set, and 2 upon decoding error.
 *
 * void clear_scheme(void);
 *		Postcondition: All allocated memory associated with the object is freed,
 *			data variables are set to the default values, and the label hash
 *			is reset to its initial state.
 *
 * size_t get_key_len(void) const;
 *		Precondition: A valid key length should already be set.
 *		Postcondition: Returns the RSA key length (modulus length).
 *
 * void get_enc_msg(uint8_t *EM) const;
 *		Precondition: An encoded message should already be set. EM should have
 *			enough memory to store the encoded message.
 *		Postcondition: The encoded message is copied into EM.
 *
 * size_t get_enc_msg_len(void) const;
 *		Precondition: An encoded message should already be set.
 *		Postcondition: Returns the length of the encoded message. This will
 *			be the same as the key length if the encoded message is valid.
 *
 * size_t get_hash_len(void) const;
 *		Postcondition: Returns the length of the output of the hash algorithm
 *			being used (SHA-256).
 *
 * void get_msg(uint8_t *M) const;
 *		Precondition: The encoded message should have already been decoded
 *			successfully. If any data variables were altered after a call
 *			to the decode function, then the function will need to be called
 *			once more. M should have enough memory to store the value of the
 *			decoded message.
 *		Postcondition: The decoded message is copied into M.
 *
 * size_t get_msg_len(void) const;
 *		Precondition: The encoded message should have already been decoded
 *			successfully.
 *		Postcondition: Returns the length of the decoded message.
 *
 * void set_hash_state(SHA256_Hash &hash);
 *		Postcondition: The entire state of hash is copied into m_Hash.
 *
 ************************************************************************/

class PKCS1_OAEP_Dec
{
	friend class RSA_OAEP;

	public:
		PKCS1_OAEP_Dec(void);
		PKCS1_OAEP_Dec(RSA_PrivKey pkey);
		PKCS1_OAEP_Dec(RSA_PrivKey pkey, uint8_t *EM, size_t EM_len,
					   uint8_t *L = NULL, size_t lLen = 0);

		int				set_key_len(RSA_PrivKey pkey);
		int				set_enc_msg(uint8_t *EM, size_t EM_len);

		void			update_label(uint8_t *L, size_t lLen);
		void			update_label(std::string L);
		void			reset_label(void);

		int				decode(void);

		void			clear_scheme(void);

		size_t			get_key_len(void) const;
		void			get_enc_msg(uint8_t *EM) const;
		size_t			get_enc_msg_len(void) const;
		size_t			get_hash_len(void) const;

		void			get_msg(uint8_t *M) const;
		size_t			get_msg_len(void) const;

	private:
		void			set_hash_state(SHA256_Hash &hash);

		size_t			m_k;			/* RSA key length */

		uint8_t			*m_EM;			/* Encoded message */
		size_t			m_EM_len;

		SHA256_Hash		m_Hash;
		size_t			m_hLen;

		uint8_t			*m_M;			/* Unencoded message */
		size_t			m_mLen;

		bool			m_key_len_set;
		bool			m_EM_len_set;
		bool			m_dec_done;
};

#endif		/* PKCS1_EME_OAEP_DEC_H */

