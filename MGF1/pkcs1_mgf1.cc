/**
 * File: pkcs1_mgf1.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Implements the member functions of the PKCS1_MGF1 class, defined in
 *			pkcs1_mgf1.h header file.
 */

#include "pkcs1_mgf1.h"

PKCS1_MGF1::PKCS1_MGF1(void)
{
	m_mask = NULL;
	m_mask_len = 0;
	m_mask_error = true;
	m_mask_done = false;
}

PKCS1_MGF1::PKCS1_MGF1(uint64_t mask_len)
{
	m_mask = NULL;
	m_mask_len = 0;

	if (set_mask_len(mask_len) == 1)
		m_mask_len = 0;
}

int PKCS1_MGF1::set_mask_len(uint64_t mask_len)
{
	m_mask_done = false;

	/* Check that mask_len doesn't exceed the
	   maximum size for the hash algorithm (sha-256) */
	if (mask_len > (0x100000000LLU * SHA256_DIGEST_LEN))
	{
		m_mask_error = true;
		return 1;
	}

	// Free m_mask memory (if any)
	if (mask_len == 0)
	{
		if (m_mask) delete[] m_mask;
		m_mask = NULL;
	}

	// Only allocate more memory if need (no shrinking)
	else if (mask_len > m_mask_len)
	{
		if (m_mask) delete[] m_mask;
		m_mask = new uint8_t[mask_len];
	}

	m_mask_len = mask_len;
	m_mask_error = false;
	
	return 0;
}

void PKCS1_MGF1::update_seed(uint8_t *mgf_seed, size_t length)
{
	return m_hash.update(mgf_seed, length);
}

void PKCS1_MGF1::update_seed(std::string mgf_seed)
{
	return m_hash.update(mgf_seed);
}

void PKCS1_MGF1::finish_mask(void)
{
	if (m_mask_error) return;

	SHA256_Hash		tmp_hash;
	size_t			buf_size;
	WORD			*buffer;

	unsigned int	ctr, ctr_stop;
	uint8_t			ctr_octet[4];
	int				conv_cnt, ext_bytes;
	uint8_t			tmp_mask_conv[4];

	/* Allocate max amount of memory needed for buffer.
	   (buffer holds concatenation of the output of
	   several calls to hash function */
	buf_size = ((m_mask_len / SHA256_DIGEST_LEN) + 1) * 8;
	buffer = new WORD[buf_size];

	/* Calculate ceil(maskLen / hLen) - 1 (See pkcs1-v2.1
	   documents). This is number of iterations of loop. */
	ctr_stop = (m_mask_len / SHA256_DIGEST_LEN) - 1;
	if (m_mask_len % SHA256_DIGEST_LEN) ctr_stop++;

	/* Hash each value of ctr separately on the already
	   computed (intermediary) hash value of the seed.
	   Store the resultant hash in the next indices of
	   buffer. */
	for (ctr = 0; ctr <= ctr_stop; ctr++)
	{
		I2OSP(ctr_octet, ctr, 4);		/* Get octet string of ctr */
		copy_hash_state(tmp_hash);		/* Intermediary hash of seed */

		tmp_hash.update(ctr_octet, 4);
		tmp_hash.finish();
		tmp_hash.get_hash_val(buffer + (ctr * 8));
	}

	conv_cnt = m_mask_len / 4;			/* Number of whole WORDS */

	/* Copy whole WORDS from buffer (concatenated hash values)
	   into m_mask. Only conv_cnt whole WORDS will fit */
	for (int i = 0; i < conv_cnt; i++)
		UINT32_TO_8(m_mask, buffer[i], i * 4)

	// Fill rest of m_mask with part of a WORD
	if ((ext_bytes = m_mask_len % 4))
	{
		UINT32_TO_8(tmp_mask_conv, buffer[conv_cnt], 0);
		memcpy(m_mask + (conv_cnt * 4), tmp_mask_conv, ext_bytes);
	}

	delete[] buffer;
	buffer = NULL;

	m_mask_done = true;		/* Necessary for get_mask function */

	return;
}

void PKCS1_MGF1::reset_mgf(uint64_t cur_len)
{
	/* Check if cur_len is a valid mask length. If it
	   is, then it will become value for m_mask_len */
	if (set_mask_len(cur_len) != 1) m_hash.reset();
	return;
}

void PKCS1_MGF1::clear_mgf(void)
{
	return reset_mgf();
}

uint64_t PKCS1_MGF1::get_mask_len(void) const
{
	return m_mask_len;
}

bool PKCS1_MGF1::valid_mask_len(void) const
{
	return !m_mask_error;
}

void PKCS1_MGF1::get_mask(uint8_t mask[]) const
{
	if (m_mask_done)
		memcpy(mask, m_mask, m_mask_len);

	return;
}

void PKCS1_MGF1::copy_hash_state(SHA256_Hash &hash_cpy) const
{
	/* Direct access of SHA256_Hash private members is
	   possible, since PKCS1_MGF1 is a class friend */

	// Copy all data variables from m_hash to hash_cpy
	memcpy(hash_cpy.m_h, m_hash.m_h, 8 * sizeof(WORD));
	memcpy(hash_cpy.m_data_buf, m_hash.m_data_buf, 64);

	hash_cpy.m_buf_fill_amt = m_hash.m_buf_fill_amt;
	hash_cpy.m_total_fill_amt = m_hash.m_total_fill_amt;
	hash_cpy.m_hash_done = m_hash.m_hash_done;

	return;
}
