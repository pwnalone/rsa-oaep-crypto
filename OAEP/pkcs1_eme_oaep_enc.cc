/**
 * File: pkcs1_eme_oaep_enc.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Implements the member functions of the PKCS1_OAEP_Enc class, defined
 *			in pkcs1_eme_oaep.h header file.
 */

#include "pkcs1_eme_oaep_enc.h"

PKCS1_OAEP_Enc::PKCS1_OAEP_Enc(void)
{
	m_EM = NULL;
	m_k = 0;
	m_M = NULL;
	m_mLen = 0;
	m_hLen = SHA256_DIGEST_LEN;

	m_valid_key_len = false;
	m_valid_msg_len = true;
	m_enc_done = false;
}

PKCS1_OAEP_Enc::PKCS1_OAEP_Enc(RSA_PubKey pkey)
{
	m_k = 0;
	m_EM = NULL;

	// Set the key length if valid
	set_key_len(pkey);

	m_M = NULL;
	m_mLen = 0;
	m_hLen = SHA256_DIGEST_LEN;

	m_valid_msg_len = true;
	m_enc_done = false;
}

PKCS1_OAEP_Enc::PKCS1_OAEP_Enc(RSA_PubKey pkey, uint8_t *M,
							   size_t mLen, uint8_t *L, size_t lLen)
{
	m_k = 0;
	m_EM = NULL;

	// If not valid key length, set default values
	if (set_key_len(pkey) == 1)
		PKCS1_OAEP_Enc();

	else
	{
		m_hLen = SHA256_DIGEST_LEN;
		m_mLen = 0;
		m_M = NULL;

		// Set message if valid length
		set_msg(M, mLen);

		// Update m_Hash with label
		update_label(L, lLen);
		m_enc_done = false;
	}
}

PKCS1_OAEP_Enc::PKCS1_OAEP_Enc(RSA_PubKey pkey, std::string M, std::string L)
{
	m_k = 0;
	m_EM = NULL;

	// If not valid key length, set default values
	if (set_key_len(pkey) == 1)
		PKCS1_OAEP_Enc();

	else
	{
		m_hLen = SHA256_DIGEST_LEN;
		m_mLen = 0;
		m_M = NULL;

		// Set message if valid length
		set_msg(M);

		// Update m_Hash with label
		update_label(L);
		m_enc_done = false;
	}
}

int PKCS1_OAEP_Enc::set_key_len(RSA_PubKey pkey)
{
	// Check that public key was successfully initialized
	if (!pkey.is_valid())
	{
		m_valid_key_len = false;
		return 1;
	}

	size_t tmp_k;

	// Get the key length (modulus length) in bytes
	tmp_k = mpz_sizeinbase(pkey.get_mod().get_mpz_t(), 2);
	tmp_k = (tmp_k % 8) ? (tmp_k / 8) + 1 : tmp_k / 8;

	// Allocate more memory for m_EM if necessary
	if (tmp_k > m_k)
	{
		if (m_EM) delete[] m_EM;
		m_EM = new uint8_t[tmp_k];
	}

	m_k = tmp_k;
	m_valid_key_len = true;
	m_enc_done = false;			/* Encoding not done anymore */

	return 0;
}

int PKCS1_OAEP_Enc::set_msg(uint8_t *M, size_t mLen)
{
	// Key length needs to be valid
	if (!m_valid_key_len) return 1;

	// Check that length of message is short enough
	if (mLen > (m_k - (2 * m_hLen) - 2))
	{
		m_valid_msg_len = false;
		return 1;
	}

	// Allocate more memory for m_M if necessary
	if (mLen > m_mLen)
	{
		if (m_M) delete[] m_M;
		m_M = new uint8_t[mLen];
	}

	// Copy message value to m_M
	memcpy(m_M, M, mLen);
	m_mLen = mLen;

	m_valid_msg_len = true;
	m_enc_done = false;			/* Encoding not done anymore */

	return 0;
}

int PKCS1_OAEP_Enc::set_msg(std::string M)
{
	// Key length needs to be valid
	if (!m_valid_key_len) return 1;

	// Check that length of message is short enough
	if (M.length() > (m_k - (2 * m_hLen) - 2))
	{
		m_valid_msg_len = false;
		return 1;
	}

	// Allocate more memory for m_M if necessary
	if (M.length() > m_mLen)
	{
		if (m_M) delete[] m_M;
		m_M = new uint8_t[M.length()];
	}

	m_mLen = M.length();

	// Copy message value to m_M
	for (int i = 0; i < m_mLen; i++)
		m_M[i] = static_cast <uint8_t> (M[i]);

	m_valid_msg_len = true;
	m_enc_done = false;			/* Encoding not done anymore */

	return 0;
}

void PKCS1_OAEP_Enc::update_label(uint8_t *L, size_t lLen)
{
	m_enc_done = false;
	return m_Hash.update(L, lLen);
}

void PKCS1_OAEP_Enc::update_label(std::string L)
{
	m_enc_done = false;
	return m_Hash.update(L);
}

void PKCS1_OAEP_Enc::reset_label(void)
{
	m_enc_done = false;
	return m_Hash.reset();
}

int PKCS1_OAEP_Enc::encode(void)
{
	// Key length and message length must be valid
	if (!m_valid_key_len || !m_valid_msg_len) return 1;

	PKCS1_MGF1				MGF;

	uint8_t					*lHash, *PS;
	uint8_t					*DB, *seed;
	uint8_t					*dbMask, *seedMask;
	size_t					PS_len, DB_len;

	static int				f_run = 1;
	static gmp_randclass	prng (gmp_randinit_default);
	mpz_class				mp_rand, sd;

#ifdef INCLUDE_SYSTIME_OK
	struct timeval			t;
#else
	mpz_class				tmp_time;
#endif

	PS_len = m_k - m_mLen - (2 * m_hLen) - 2;
	DB_len = m_k - m_hLen - 1;

	// Allocate memory for temporary variables
	lHash = new uint8_t[m_hLen];
	PS = new uint8_t[PS_len];
	DB = new uint8_t[DB_len];
	seed = new uint8_t[m_hLen];
	dbMask = new uint8_t[DB_len];
	seedMask = new uint8_t[m_hLen];

	// Seed random number generator on first call of function
	if (f_run)
	{
#ifdef INCLUDE_SYSTIME_OK
		/* Using gettimeofday() rather than time() gives
		   a more random seed value for gmp prng */
		gettimeofday(&t, NULL);
		sd = t.tv_sec * t.tv_usec;
#else
		tmp_time = static_cast <int> (time(NULL));
		sd = tmp_time * tmp_time;
#endif

		prng.seed(sd);
		f_run = 0;
	}

	// Finish hash of label and copy value to lHash
	m_Hash.finish();
	m_Hash.get_hash_val(lHash);

	// Set 0x00 value bytes to PS
	memset(PS, 0x00, PS_len);

	/* DB = lHash || PS || 0x01 || M
	   (Here '||' denotes concatenation) */
	memcpy(DB, lHash, m_hLen);
	memcpy(DB + m_hLen, PS, PS_len);
	DB[m_hLen + PS_len] = 0x01;
	memcpy(DB + m_hLen + PS_len + 1, m_M, m_mLen);

	// Get random seed value (hLen length octet string)
	mp_rand = prng.get_z_bits(m_hLen * 8);
	I2OSP(seed, mp_rand, m_hLen);

	// Get mask of seed and copy to dbMask
	MGF.set_mask_len(DB_len);
	MGF.update_seed(seed, m_hLen);
	MGF.finish_mask();
	MGF.get_mask(dbMask);

	// Xor DB with dbMask
	for (int i = 0; i < DB_len; i++)
		DB[i] ^= dbMask[i];

	/* Get mask of new DB value (xored
	   value) and copy to seedMask */
	MGF.reset_mgf(m_hLen);
	MGF.update_seed(DB, DB_len);
	MGF.finish_mask();
	MGF.get_mask(seedMask);
	MGF.clear_mgf();

	// Xor seed with seedMask
	for (int i = 0; i < m_hLen; i++)
		seed[i] ^= seedMask[i];

	/* EM = 0x00 || seed (xored value) || DB (xored value)
	   (Here '||' denotes concatenation) */
	m_EM[0] = 0x00;
	memcpy(m_EM + 1, seed, m_hLen);
	memcpy(m_EM + 1 + m_hLen, DB, DB_len);

	// Free memory of all temporary variables
	delete[] lHash;
	delete[] PS;
	delete[] DB;
	delete[] seed;
	delete[] dbMask;
	delete[] seedMask;

	m_enc_done = true;		/* Encoding is done */

	return 0;
}

void PKCS1_OAEP_Enc::clear_scheme(void)
{
	// Free memory of m_EM and ground pointer to NULL
	if (m_EM) delete[] m_EM;
	m_EM = NULL;

	// Free memory of m_M and ground pointer to NULL
	if (m_M) delete[] m_M;
	m_M = NULL;

	// Set default values and reset label hash
	m_k = 0;
	m_mLen = 0;
	m_hLen = SHA256_DIGEST_LEN;

	m_Hash.reset();

	m_valid_key_len = false;
	m_valid_msg_len = true;
	m_enc_done = false;

	return;
}

size_t PKCS1_OAEP_Enc::get_key_len(void) const
{
	return m_k;
}

void PKCS1_OAEP_Enc::get_msg(uint8_t *M) const
{
	memcpy(M, m_M, m_mLen);
	return;
}

size_t PKCS1_OAEP_Enc::get_msg_len(void) const
{
	return m_mLen;
}

size_t PKCS1_OAEP_Enc::get_hash_len(void) const
{
	return m_hLen;
}

void PKCS1_OAEP_Enc::get_enc_msg(uint8_t *EM) const
{
	/* Copy EME-OAEP padded message to
	   EM only if encoding is done */
	if (m_enc_done)
		memcpy(EM, m_EM, m_k);

	return;
}

void PKCS1_OAEP_Enc::set_hash_state(SHA256_Hash &hash)
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
