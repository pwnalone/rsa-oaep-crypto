/**
 * File: pkcs1_mgf1.h
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Defines the PKCS1_MGF1 class which contains functions for generating
 *			random masks of specified lengths using the SHA-256 hashing algorithm.
 *		- Generating a mask is optimized in finish_mask member function of the
 *			PKCS1_MGF1 class by copying a base hash state rather than performing
 *			the SHA-256 hashing algorithm repeatedly.
 */

#ifndef PKCS1_MGF1_H
#define PKCS1_MGF1_H

#include <string>
#include <stdint.h>

#include "../Data_Conv/data_conv_prims.h"
#include "../SHA256/sha256.h"

/************************* class PKCS1_MGF1 *************************
 *
 * PKCS1_MGF1(void);
 *		Postcondition: All data members are set to default values (false, 0).
 *			m_mask_error is set to true.
 *
 * PKCS1_MGF1(uint64_t mask_len);
 *		Precondition: mask_len should not be greater than
 *			2^32 * SHA256_DIGEST_LEN.
 *		Postcondition: Same as above constructor, except m_mask_len is set
 *			to mask_len if mask_len is a valid mask length. Memory is
 *			allocated for a mask of m_mask_len size. m_mask_error is set to
 *			false if mask_len is a valid mask length.
 *
 * int set_mask_len(uint64_t mask_len);
 *		Precondition: mask_len should not be greater than
 *			2^32 * SHA256_DIGEST_LEN.
 *		Postcondition: Assigns value of mask_len to m_mask_len if mask_len
 *			is a valid mask length. Allocates more memory if needed. Frees
 *			memory of mask if mask_len is 0. Sets m_mask_error to true if
 *			mask_len is an invalid mask. Returns 0 upon successfull
 *			initialization of m_mask_len, and 1 otherwise.
 *
 * void	update_seed(uint8_t *mgf_seed, size_t length);
 *		Precondition: mgf_seed has at least length number of uint8_t values.
 *		Postcondition: hash value of m_hash is updated with mgf_seed.
 *
 * void update_seed(std::string mgf_seed);
 *		Postcondition: hash value of m_hash is updated with all of mgf_seed.
 *
 * void finish_mask(void);
 *		Precondition: m_mask_error must be false, meaning that m_mask_len
 *			was initialized to a valid mask length.
 *		Postcondition: A mask of m_mask_len length is generated using a hash
 *			algorithm (sha-256), and is stored in the memory pointed to by
 *			m_mask.
 *
 * void reset_mgf(uint64_t cur_len = 0);
 *		Precondition: cur_len should not be greater than
 *			2^32 * SHA256_DIGEST_LEN.
 *		Postcondition: Calls set_mask_len function. If set_mask_len
 *			initializes m_mask_len successfully, then m_hash is reset.
 *
 * void clear_mgf(void);
 *		Postcondition: Deletes all allocated memory for the object. This
 *			function should be called whenever the object is no longer of
 *			any use. Equivalent to reset_mgf(0).
 *
 * uint64_t get_mask_len(void) const;
 *		Precondition: A valid mask length should be set.
 *		Postcondition: Returns current mask length (m_mask_len).
 *
 * bool valid_mask_len(void) const;
 *		Postcondition: Returns true if the current mask length is valid,
 *			and false otherwise. Function will return false, if an
 *			earlier call to set_mask_len failed, since set_mask_len sets
 *			m_mask_error to true upon failure, but doesn't alter the value
 *			of m_mask_len.
 *
 * void get_mask(uint8_t mask[]) const;
 *		Precondition: m_mask_done should be true, signifying that a mask
 *			has already been produced. mask should have enough memory to
 *			store a mask of length m_mask_len.
 *		Postcondition: mask is filled with an m_mask_len length mask value.
 *
 * void copy_hash_state(SHA256_Hash &hash_cpy) const;
 *		Postcondition: The current state of m_hash is copied into the
 *			hash_cpy object. This function is used for optimizing the
 *			finish_mask function.
 *
 ********************************************************************/

class PKCS1_MGF1
{
	public:
		PKCS1_MGF1(void);
		PKCS1_MGF1(uint64_t mask_len);

		int				set_mask_len(uint64_t mask_len);

		void			update_seed(uint8_t *mgf_seed, size_t length);
		void			update_seed(std::string mgf_seed);

		void			finish_mask(void);
		void			reset_mgf(uint64_t cur_len = 0);
		void			clear_mgf(void);

		uint64_t		get_mask_len(void) const;
		bool			valid_mask_len(void) const;
		void			get_mask(uint8_t mask[]) const;

	private:
		void			copy_hash_state(SHA256_Hash &hash_cpy) const;

		SHA256_Hash		m_hash;
		uint8_t			*m_mask;

		uint64_t		m_mask_len;
		bool			m_mask_error;
		bool			m_mask_done;
};

#endif		/* PKCS1_MGF1_H */
