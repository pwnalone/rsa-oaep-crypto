/**
 * File: rsa_oaep.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Implements the member functions of the RSA_OAEP class, defined in
 *			rsa_oaep.h header file.
 */

#include "rsa_oaep.h"

RSA_OAEP::RSA_OAEP(void)
{
	m_C = 0;

	m_pub_key_set = false;
	m_priv_key_set = false;
	m_cipher_set = false;
}

RSA_OAEP::RSA_OAEP(RSA_Primes ppair)
{
	m_C = 0;
	gen_keys(ppair);
	m_cipher_set = false;
}

RSA_OAEP::RSA_OAEP(RSA_PubKey pub_k)
{
	m_C = 0;

	// Set public key if valid only
	if (set_pubkey(pub_k) == 1)
		m_pub_key_set = false;

	m_priv_key_set = false;
	m_cipher_set = false;
}

RSA_OAEP::RSA_OAEP(RSA_PrivKey priv_k)
{
	m_C = 0;

	// Set private key if it has at least a valid pair
	if (set_privkey(priv_k) == 1)
		m_priv_key_set = false;

	m_pub_key_set = false;
	m_cipher_set = false;
}

RSA_OAEP::RSA_OAEP(RSA_PubKey pub_k, RSA_PrivKey priv_k)
{
	int result;

	m_C = 0;
	result = set_keys(pub_k, priv_k);

	// Check if either key wasn't set
	if (result & 1) m_pub_key_set = false;
	if (result & 2) m_priv_key_set = false;

	m_cipher_set = false;
}

void RSA_OAEP::gen_keys(void)
{
	RSA_Primes ppair;
	return gen_keys(ppair);
}

void RSA_OAEP::gen_keys(RSA_Primes ppair)
{
	// Generate key pairs using ppair
	m_pub_key.gen_pair(ppair);
	m_priv_key.gen_pair(ppair, m_pub_key);

	m_pub_key_set = true;
	m_priv_key_set = true;

	// Set OAEP encoding and decoding schemes key lengths
	m_enc_scheme.set_key_len(m_pub_key);
	m_dec_scheme.set_key_len(m_priv_key);

	return;
}

int RSA_OAEP::set_pubkey(RSA_PubKey pub_k)
{
	if (!pub_k.is_valid()) return 1;

	mpz_class exp (pub_k.get_exp());
	mpz_class mod (pub_k.get_mod());

	// Set the public key pair
	m_pub_key.set_pair(exp, mod);
	m_pub_key_set = true;

	// Set OAEP encoding scheme key length
	m_enc_scheme.set_key_len(m_pub_key);

	return 0;
}

int RSA_OAEP::set_privkey(RSA_PrivKey priv_k)
{
	// Set the RSA key pair and CRT values if possible
	int err_val = copy_privkey(m_priv_key, priv_k);

	/* Set OAEP decoding scheme key length only
	   if the private key was successfully set */
	if (!err_val)
	{
		m_priv_key_set = true;
		m_dec_scheme.set_key_len(m_priv_key);
	}

	return err_val;
}

int RSA_OAEP::set_keys(RSA_PubKey pub_k, RSA_PrivKey priv_k)
{
	/* [0 (00) = both valid] [1 (01) = public valid]
	   [2 (10) = private valid] [3 (11) = none valid] */
	int result = set_pubkey(pub_k);
	return (result | (set_privkey(priv_k) << 1));
}

int RSA_OAEP::set_msg(uint8_t *M, size_t mLen)
{
	return m_enc_scheme.set_msg(M, mLen);
}

int RSA_OAEP::set_msg(std::string M)
{
	return m_enc_scheme.set_msg(M);
}

int RSA_OAEP::set_cipher(uint8_t *C, size_t cLen)
{
	mpz_class tmp_C;
	OS2IP(tmp_C, C, cLen);
	return set_cipher(tmp_C);
}

int RSA_OAEP::set_cipher(mpz_class C)
{
	// Cipher has to be less than modulus
	if (C > m_priv_key.get_mod()) return 1;

	m_C = C;
	m_cipher_set = true;

	return 0;
}

void RSA_OAEP::update_label(uint8_t *L, size_t lLen)
{
	return m_Hash.update(L, lLen);
}

void RSA_OAEP::update_label(std::string L)
{
	return m_Hash.update(L);
}

void RSA_OAEP::reset_label(void)
{
	return m_Hash.reset();
}

int RSA_OAEP::encrypt(uint8_t **C, size_t &cLen)
{
	mpz_class	tmp_C;
	mpz_class	C_cpy;

	// Store RSA-OAEP encrypted message in tmp_C
	if (encrypt(tmp_C) == 1) return 1;

	C_cpy = tmp_C;
	cLen = m_enc_scheme.get_key_len();

	// Convert cipher into an octet string
	*C = new uint8_t[cLen];
	I2OSP(*C, tmp_C, cLen);

	return 0;
}

int RSA_OAEP::encrypt(mpz_class &C)
{
	if (!m_pub_key_set) return 1;

	int			enc_err_val;

	uint8_t		*EM;
	size_t		EM_len;
	mpz_class	EM_int;

	/* Copy the label hash state over to OAEP
	   encoding scheme and encode message */
	m_enc_scheme.set_hash_state(this->m_Hash);
	if (m_enc_scheme.encode() == 1) return 1;

	EM_len = m_enc_scheme.get_key_len();
	EM = new uint8_t[EM_len];

	// Convert encoded message to an integer
	m_enc_scheme.get_enc_msg(EM);
	OS2IP(EM_int, EM, EM_len);

	// Encrypt the encoded message using RSA encrytion
	enc_err_val = m_pub_key.encrypt(C, EM_int);

	// Free allocated memory
	delete[] EM;
	EM = NULL;

	/* RSA encryption error [0 = none, 1 = error] */
	return enc_err_val;
}

int RSA_OAEP::decrypt(uint8_t **M, size_t &mLen)
{
	if (!m_priv_key_set) return 1;

	int			dec_err_val;

	mpz_class	EM_int;
	uint8_t		*EM;
	size_t		EM_len;

	// Return error code if RSA decryption fails
	if (m_priv_key.decrypt(EM_int, m_C) == 1) return 1;

	/* Convert decrypted OAEP-encoded
	   message into an octet string */
	EM_len = m_dec_scheme.get_key_len();
	EM = new uint8_t[EM_len];
	I2OSP(EM, EM_int, EM_len);

	// Decode OAEP-encoded message
	m_dec_scheme.set_enc_msg(EM, EM_len);
	m_dec_scheme.set_hash_state(this->m_Hash);
	dec_err_val = m_dec_scheme.decode();

	/* Store decoded message in M if
	   OAEP-decoding was successful */
	if (!dec_err_val)
	{
		mLen = m_dec_scheme.get_msg_len();
		*M = new uint8_t[mLen];
		m_dec_scheme.get_msg(*M);
	}

	// Free allocated memory
	delete[] EM;
	EM = NULL;

	/* OAEP-decoding error [0 = none, 1 = error] */
	return (dec_err_val) ? 1 : 0;
}

int RSA_OAEP::decrypt(mpz_class &M)
{
	uint8_t		*tmp_M;
	size_t		tmp_mLen;

	/* If decryption was successful then convert
	   message, tmp_M, into an octet string */
	if (decrypt(&tmp_M, tmp_mLen) == 1) return 1;
	OS2IP(M, tmp_M, tmp_mLen);

	// Free allocated memory
	delete[] tmp_M;
	tmp_M = NULL;
	
	return 0;
}

void RSA_OAEP::clear(void)
{
	m_C = 0;
	
	/* Restore public/private key data
	   variables to default values */
	m_pub_key.reset();
	m_priv_key.reset();

	// Free all memory associated with OAEP schemes
	m_enc_scheme.clear_scheme();
	m_dec_scheme.clear_scheme();

	// Reset label hash to its initial state
	m_Hash.reset();

	m_pub_key_set = false;
	m_priv_key_set = false;
	m_cipher_set = false;

	return;
}

void RSA_OAEP::get_pubkey(RSA_PubKey &pub_k)
{
	if (!m_pub_key.is_valid()) return;

	mpz_class	exp (m_pub_key.get_exp());
	mpz_class	mod (m_pub_key.get_mod());

	// Set pub_k with object's public key pair
	pub_k.set_pair(exp, mod);

	return;
}

void RSA_OAEP::get_privkey(RSA_PrivKey &priv_k)
{
	copy_privkey(priv_k, m_priv_key);
	return;
}

int RSA_OAEP::copy_privkey(RSA_PrivKey &cpy, RSA_PrivKey pkey)
{
	// pkey must have at least a valid key pair
	if (!pkey.has_pair()) return 1;

	mpz_class	exp, mod;
	mpz_class	p, q;
	mpz_class	dp, dq, qinv;

	exp = pkey.get_exp();
	mod = pkey.get_mod();

	// Set cpy with pkey's key pair
	cpy.set_pair(exp, mod);

	// If pkey has CRT values, then set cpy with them
	if (pkey.has_crt_vals())
	{
		p = pkey.get_prime_p();
		q = pkey.get_prime_q();

		dp = pkey.get_crt_dp();
		dq = pkey.get_crt_dq();
		qinv = pkey.get_crt_qinv();

		/* No error checking that CRT values are valid */
		cpy.set_crt_vals(p, q, dp, dq, qinv);
	}

	return 0;
}
