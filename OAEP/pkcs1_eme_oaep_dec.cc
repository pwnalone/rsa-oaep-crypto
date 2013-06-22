/**
 * File: pkcs1_eme_oaep_dec.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Implements the member functions of the PKCS1_OAEP_Dec class, defined
 *			in pkcs1_eme_oaep_dec.h header file.
 */

#include "pkcs1_eme_oaep_dec.h"

PKCS1_OAEP_Dec::PKCS1_OAEP_Dec(void)
{
	m_k = 0;

	m_EM = NULL;
	m_EM_len = 0;
	m_hLen = SHA256_DIGEST_LEN;

	m_M = NULL;
	m_mLen = 0;

	m_key_len_set = false;
	m_EM_len_set = false;
	m_dec_done = false;
}

PKCS1_OAEP_Dec::PKCS1_OAEP_Dec(RSA_PrivKey pkey)
{
	m_k = 0;
	m_hLen = SHA256_DIGEST_LEN;

	// Set the key length if valid
	set_key_len(pkey);

	m_EM = NULL;
	m_EM_len = 0;

	m_M = NULL;
	m_mLen = 0;

	m_EM_len_set = false;
	m_dec_done = false;
}

PKCS1_OAEP_Dec::PKCS1_OAEP_Dec(RSA_PrivKey pkey, uint8_t *EM,
							   size_t EM_len, uint8_t *L, size_t lLen)
{
	m_k = 0;
	m_hLen = SHA256_DIGEST_LEN;

	// If not valid key length, set default values
	if (set_key_len(pkey) == 1)
		PKCS1_OAEP_Dec();

	else
	{
		m_EM = NULL;
		m_EM_len = 0;

		// Set encoded message if valid length
		set_enc_msg(EM, EM_len);

		m_M = NULL;
		m_mLen = 0;

		// Update m_Hash with label
		update_label(L, lLen);
		m_dec_done = false;
	}
}

int PKCS1_OAEP_Dec::set_key_len(RSA_PrivKey pkey)
{
	// Check that private key was successfully initialized
	if (!pkey.is_valid())
	{
		m_key_len_set = false;
		return 1;
	}

	size_t tmp_k;

	// Get the key length (modulus length) in bytes
	tmp_k = mpz_sizeinbase(pkey.get_mod().get_mpz_t(), 2);
	tmp_k = (tmp_k % 8) ? (tmp_k / 8) + 1 : tmp_k / 8;
	
	// Check that key length is valid
	if (tmp_k < ((2 * m_hLen) + 2))
	{
		m_key_len_set = false;
		return 1;
	}

	m_k = tmp_k;

	m_key_len_set = true;
	m_EM_len_set = false;		/* New key length might not be same */
	m_dec_done = false;			/* Decoding not done anymore */

	return 0;
}

int PKCS1_OAEP_Dec::set_enc_msg(uint8_t *EM, size_t EM_len)
{
	/* Check that a key length has been set and that the
	   length of the encoded message equals the key length */
	if (!m_key_len_set || EM_len != m_k)
	{
		m_EM_len_set = false;
		return 1;
	}

	// Allocate more memory for the encoded message if necessary
	if (EM_len > m_EM_len)
	{
		if (m_EM) delete[] m_EM;
		m_EM = new uint8_t[EM_len];
	}

	memcpy(m_EM, EM, EM_len);
	m_EM_len = EM_len;

	m_EM_len_set = true;
	m_dec_done = false;			/* Decoding not done anymore */

	return 0;
}

void PKCS1_OAEP_Dec::update_label(uint8_t *L, size_t lLen)
{
	m_dec_done = false;
	return m_Hash.update(L, lLen);
}

void PKCS1_OAEP_Dec::update_label(std::string L)
{
	m_dec_done = false;
	return m_Hash.update(L);
}

void PKCS1_OAEP_Dec::reset_label(void)
{
	m_dec_done = false;
	return m_Hash.reset();
}

int PKCS1_OAEP_Dec::decode(void)
{
	/* Don't decode unless valid key length
	   and encoded message are set */
	if (!m_key_len_set || !m_EM_len_set)
		return 1;

	PKCS1_MGF1		MGF;
	int				err_val = 0;

	uint8_t			*seed, *DB;
	uint8_t			*seedMask, *dbMask;
	size_t			DB_len, PS_end;
	uint8_t			*lHash, *lHash_cmp;

	DB_len = m_k - m_hLen - 1;
	PS_end = m_hLen;

	// Allocate memory for temporary variables
	seed = new uint8_t[m_hLen];
	DB = new uint8_t[DB_len];
	seedMask = new uint8_t[m_hLen];
	dbMask = new uint8_t[DB_len];

	lHash = new uint8_t[m_hLen];
	lHash_cmp = new uint8_t[m_hLen];

	// Finish hash of label and copy value to lHash
	m_Hash.finish();
	m_Hash.get_hash_val(lHash);

	/* Store the masked seed value from EM in seed,
	   and store the masked DB value from EM in DB */
	memcpy(seed, m_EM + 1, m_hLen);
	memcpy(DB, m_EM + 1 + m_hLen, DB_len);

	// Generate a seed mask from the masked DB value
	MGF.set_mask_len(m_hLen);
	MGF.update_seed(DB, DB_len);
	MGF.finish_mask();
	MGF.get_mask(seedMask);

	/* Get the original seed value by xoring the masked seed
	   value with the seed mask generated from masked DB */
	for (int i = 0; i < m_hLen; i++)
		seed[i] ^= seedMask[i];

	// Generate a DB mask from the original seed value
	MGF.reset_mgf(DB_len);
	MGF.update_seed(seed, m_hLen);
	MGF.finish_mask();
	MGF.get_mask(dbMask);
	MGF.clear_mgf();

	/* Get the original DB value (padded message) by xoring the
	   masked DB value with the DB mask generated from the seed */
	for (int i = 0; i < DB_len; i++)
		DB[i] ^= dbMask[i];

	// Get the hash part of DB value for later comparison
	memcpy(lHash_cmp, DB, m_hLen);

	// Find the end of PS part of DB (and beginning of message)
	while (DB[PS_end] == 0x00)
		PS_end++;

	// Get the message and its length
	m_mLen = DB_len - (PS_end + 1);
	m_M = new uint8_t[m_mLen];
	memcpy(m_M, DB + PS_end + 1, m_mLen);

	// Determine if the decoded message is valid
	if (m_EM[0] != 0x00) err_val = 2;
	else if (DB[PS_end] != 0x01) err_val = 2;

	else
	{
		// Compare label hash values
		for (int i = 0; i < m_hLen; i++)
		{
			if (lHash[i] != lHash_cmp[i])
			{
				err_val = 2;
				break;
			}
		}
	}

	/* If there was a decoding error, free memory for the message
	   and its length and reset their variables to default values */
	/* Holding off errors until the end prevents timing attacks */
	if (err_val)
	{
		delete[] m_M;
		m_M = NULL;
		m_mLen = 0;
	}
	else m_dec_done = true;

	// Free memory of all temporary variables
	delete[] seed;
	delete[] DB;
	delete[] seedMask;
	delete[] dbMask;
	delete[] lHash;
	delete[] lHash_cmp;

	return err_val;			/* [0 = no error, 2 = decoding error] */
}

void PKCS1_OAEP_Dec::clear_scheme(void)
{
	// Free memory of m_EM and ground pointer to NULL
	if (m_EM) delete[] m_EM;
	m_EM = NULL;

	// Free memory of m_M and ground pointer to NULL
	if (m_M) delete[] m_M;
	m_M = NULL;

	// Set default values and reset label hash
	m_k = 0;
	m_EM_len = 0;
	m_mLen = 0;

	m_Hash.reset();
	m_hLen = SHA256_DIGEST_LEN;

	m_key_len_set = false;
	m_EM_len_set = false;
	m_dec_done = false;

	return;
}

size_t PKCS1_OAEP_Dec::get_key_len(void) const
{
	return m_k;
}

void PKCS1_OAEP_Dec::get_enc_msg(uint8_t *EM) const
{
	if (m_EM_len_set)
		memcpy(EM, m_EM, m_EM_len);

	return;
}

size_t PKCS1_OAEP_Dec::get_enc_msg_len(void) const
{
	return m_EM_len;
}

size_t PKCS1_OAEP_Dec::get_hash_len(void) const
{
	return m_hLen;
}

void PKCS1_OAEP_Dec::get_msg(uint8_t *M) const
{
	/* Copy EME-OAEP decoded message to
	   M only if decoding is done */
	if (m_dec_done)
		memcpy(M, m_M, m_mLen);

	return;
}

size_t PKCS1_OAEP_Dec::get_msg_len(void) const
{
	return m_mLen;
}

void PKCS1_OAEP_Dec::set_hash_state(SHA256_Hash &hash)
{
	/* Direct access of SHA256_Hash private members is
	   possible, since PKCS1_OAEP_Enc is a class friend */

	// Copy all data variables from hash to m_Hash
	memcpy(m_Hash.m_h, hash.m_h, 8 * sizeof(WORD));
	memcpy(m_Hash.m_data_buf, hash.m_data_buf, 64);

	m_Hash.m_buf_fill_amt = hash.m_buf_fill_amt;
	m_Hash.m_total_fill_amt = hash.m_total_fill_amt;
	m_Hash.m_hash_done = hash.m_hash_done;

	return;
}
