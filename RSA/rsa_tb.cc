/**
 * File: rsa_tb.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Implements the member functions of the RSA_Primes class, defined in
 *			rsa_tb.h header file.
 *		- Implements the member functions of the RSA_PubKey class, defined in
 *			rsa_tb.h header file.
 *		- Implements the member functions of the RSA_PrivKey class, defined in
 *			rsa_tb.h header file.
 */

#include "rsa_tb.h"

/*** RSA_Primes */

RSA_Primes::RSA_Primes(void)
{
	gen_primes();
}

void RSA_Primes::gen_primes(void)
{
	static int				f_run = 1;
	static gmp_randclass	prng (gmp_randinit_default);
	mpz_class				sd, mp_rand;

#ifdef INCLUDE_SYSTIME_OK
	struct timeval			t;
#else
	mpz_class				tmp_time;
#endif

	// Seed GMP prng on first run of function only
	if (f_run)
	{
#ifdef INCLUDE_SYSTIME_OK
		/* Using gettimeofday() rather than time() gives
		   a more random seed value for gmp prng */
		gettimeofday(&t, NULL);
		sd = t.tv_sec * t.tv_usec;
#else
		tmp_time = static_cast <unsigned int> (time(NULL));
		sd = tmp_time * tmp_time;
#endif

		prng.seed(sd);
		f_run = 0;
	}

	// Get two random primes of PRIME_SIZE bits
	mp_rand = prng.get_z_bits(PRIME_SIZE);
	mpz_nextprime(m_p.get_mpz_t(), mp_rand.get_mpz_t());

	mp_rand = prng.get_z_bits(PRIME_SIZE);
	mpz_nextprime(m_q.get_mpz_t(), mp_rand.get_mpz_t());

	// Calculate prime product and phi of the product
	m_n = m_p * m_q;
	m_m = (m_p - 1) * (m_q - 1);

	return;
}

mpz_class RSA_Primes::get_prime_p(void) const
{
	return m_p;
}

mpz_class RSA_Primes::get_prime_q(void) const
{
	return m_q;
}

mpz_class RSA_Primes::get_n(void) const
{
	return m_n;
}

mpz_class RSA_Primes::get_phi_of_n(void) const
{
	return m_m;
}

/*** RSA_PubKey */

RSA_PubKey::RSA_PubKey(void)
{
	m_exp = 0;
	m_mod = 0;

	m_pair_set = false;
}

RSA_PubKey::RSA_PubKey(RSA_Primes ppair)
{
	gen_pair(ppair);
}

RSA_PubKey::RSA_PubKey(mpz_class exp, mpz_class mod)
{
	if (set_pair(exp, mod) == 1)
		RSA_PubKey();
}

void RSA_PubKey::gen_pair(RSA_Primes ppair)
{
	mpz_class		m (ppair.get_phi_of_n());
	unsigned long	i;

	/* Find a value that is relatively prime to m value */
	/* If E_DEFAULT_VAL isn't relatively prime, then the
	   first relatively prime value after is selected */
	for (i = E_DEFAULT_VAL; i < ULONG_MAX; i++)
	{
		if (mpz_gcd_ui(NULL, m.get_mpz_t(), i) == 1)
			break;
	}

	// Set public exponent and modulus
	m_exp = i;
	m_mod = ppair.get_n();

	m_pair_set = true;

	return;
}

int RSA_PubKey::set_pair(mpz_class exp, mpz_class mod)
{
	if (exp >= mod) return 1;

	m_exp = exp;
	m_mod = mod;

	m_pair_set = true;

	return 0;
}

int RSA_PubKey::encrypt(mpz_class &c, mpz_class m) const
{
	if (!m_pair_set || m >= m_mod) return 1;

	// Perform encryption operation: c = m^e (mod n)
	mpz_powm(c.get_mpz_t(), m.get_mpz_t(),
			 m_exp.get_mpz_t(), m_mod.get_mpz_t());

	return 0;
}

void RSA_PubKey::reset(void)
{
	RSA_PubKey();
	return;
}

mpz_class RSA_PubKey::get_exp(void) const
{
	return m_exp;
}

mpz_class RSA_PubKey::get_mod(void) const
{
	return m_mod;
}

bool RSA_PubKey::is_valid(void) const
{
	return m_pair_set;
}

/*** RSA_PrivKey */

RSA_PrivKey::RSA_PrivKey(void)
{
	m_exp = 0;
	m_mod = 0;

	m_p = m_q = 0;
	m_crt_dp = m_crt_dq = m_crt_qinv = 0;

	m_pair_set = false;
	m_crt_set = false;
}

RSA_PrivKey::RSA_PrivKey(RSA_Primes ppair, RSA_PubKey pub_k)
{
	int err_val = gen_pair(ppair, pub_k);

	// Handle errors from gen_pair function
	if (err_val == 1) RSA_PrivKey();
	else if (err_val == 2)
	{
		m_p = m_q = 0;
		m_crt_dp = m_crt_dq = m_crt_qinv = 0;
		m_crt_set = false;
	}
}

RSA_PrivKey::RSA_PrivKey(mpz_class exp, mpz_class mod)
{
	// Set exp and mod as public exponent and modulus if valid
	if (set_pair(exp, mod) == 1)
	{
		m_exp = 0;
		m_mod = 0;
		m_pair_set = false;
	}

	m_p = m_q = 0;
	m_crt_dp = m_crt_dq = m_crt_qinv = 0;
	m_crt_set = false;
}

RSA_PrivKey::RSA_PrivKey(mpz_class p, mpz_class q, mpz_class dp,
						 mpz_class dq, mpz_class qinv)
{
	m_exp = 0;
	m_mod = 0;
	m_pair_set = false;

	/* No error checking possible (as far as I know of) */
	set_crt_vals(p, q, dp, dq, qinv);
}

int RSA_PrivKey::gen_pair(RSA_Primes ppair, RSA_PubKey pub_k)
{
	if (!pub_k.is_valid()) return 1;

	mpz_class	e (pub_k.get_exp());
	mpz_class	m (ppair.get_phi_of_n());
	
	mpz_class	p, q;

	/* Calculate the private exponent by finding the
	   inverse of the public exponent: d = d^-1 (mod m) */
	if (!mpz_invert(m_exp.get_mpz_t(), e.get_mpz_t(), m.get_mpz_t()))
		return 1;
	
	// Set private key pair (decryption possible)
	m_mod = pub_k.get_mod();
	m_pair_set = true;

	p = ppair.get_prime_p();
	q = ppair.get_prime_q();

	/* Calculate the Chinese Remainder Theorem (CTR)
	   value, qinv (prime q inverse): qinv = q^-1 (mod p) */
	if (!mpz_invert(m_crt_qinv.get_mpz_t(), q.get_mpz_t(), p.get_mpz_t()))
		return 2;

	// Set CRT values (decryption optimized)
	m_p = p;
	m_q = q;

	m_crt_dp = m_exp % (p - 1);
	m_crt_dq = m_exp % (q - 1);
	m_crt_set = true;

	return 0;
}

void RSA_PrivKey::set_crt_vals(mpz_class p, mpz_class q, mpz_class dp,
							   mpz_class dq, mpz_class qinv)
{
	m_p = p;
	m_q = q;

	m_crt_dp = dp;
	m_crt_dq = dq;
	m_crt_qinv = qinv;

	m_crt_set = true;
	
	return;
}

int RSA_PrivKey::decrypt(mpz_class &m, mpz_class c) const
{
	if ((!m_pair_set && !m_crt_set) || c >= m_mod) return 1;

	mpz_class	m1, m2;
	mpz_class	h;

	// With CRT values, decryption is faster
	if (m_crt_set)
	{
		/* See wikipedia documentation for Chinese Remainder
		   Algorithm: http://en.wikipedia.org/wiki/RSA_(algorithm) */
		mpz_powm(m1.get_mpz_t(), c.get_mpz_t(),
				 m_crt_dp.get_mpz_t(), m_p.get_mpz_t());
		mpz_powm(m2.get_mpz_t(), c.get_mpz_t(),
				 m_crt_dq.get_mpz_t(), m_q.get_mpz_t());

		if (m1 < m2) h = (m_crt_qinv * (m1 + m_p - m2)) % m_p;
		else h = (m_crt_qinv * (m1 - m2)) % m_p;

		/* Necessary so that h won't be a negative value */
		if (h < 0) h += m_p;

		m = m2 + (h * m_q);
	}

	// Otherwise use regular decryption formula: m = c^d (mod n)
	else
	{
		mpz_powm(m.get_mpz_t(), c.get_mpz_t(),
				 m_exp.get_mpz_t(), m_mod.get_mpz_t());
	}

	return 0;
}

void RSA_PrivKey::reset(void)
{
	RSA_PrivKey();
	return;
}

mpz_class RSA_PrivKey::get_prime_p(void) const
{
	return m_p;
}

mpz_class RSA_PrivKey::get_prime_q(void) const
{
	return m_q;
}

mpz_class RSA_PrivKey::get_crt_dp(void) const
{
	return m_crt_dp;
}

mpz_class RSA_PrivKey::get_crt_dq(void) const
{
	return m_crt_dq;
}

mpz_class RSA_PrivKey::get_crt_qinv(void) const
{
	return m_crt_qinv;
}

bool RSA_PrivKey::is_valid(void) const
{
	return (m_pair_set || m_crt_set);
}

bool RSA_PrivKey::has_pair(void) const
{
	return m_pair_set;
}

bool RSA_PrivKey::has_crt_vals(void) const
{
	return m_crt_set;
}

bool RSA_PrivKey::is_complete(void) const
{
	return (m_pair_set && m_crt_set);
}

/*** Other */

void RSA_gen_key_pairs(RSA_PubKey &pub_k, RSA_PrivKey &priv_k)
{
	RSA_Primes ppair;

	pub_k.gen_pair(ppair);
	priv_k.gen_pair(ppair, pub_k);

	return;
}
