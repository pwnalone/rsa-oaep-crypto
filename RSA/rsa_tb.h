/**
 * File: rsa_tb.h
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Defines the RSA_Primes class which contains functions for generating
 *			large random prime numbers to be used in RSA key generation.
 *		- Defines the RSA_PubKey class which contains functions for encrypting
 *			messages using the RSA encryption algorithm.
 *		- Defines the RSA_PrivKey class which contains functions for decrypting
 *			messages using the RSA decryption algorithm.
 *		- RSA decryption is optimized in the RSA_PrivKey class by using the
 *			Chinese Remainder Algorithm by default if the Chinese Remainder
 *			Theorem (CRT) values are present.
 */

#ifndef RSA_TB_H
#define RSA_TB_H

#include <climits>
#include <iostream>
#include <string>
#include <gmpxx.h>		/* GMP C++ Library */

/* Determine whether system has unistd.h header file, which
   defines macros to test for POSIX compatibility. */
/* [Code taken from: http://nadeausoftware.com/articles/2012/01/
   c_c_tip_how_use_compiler_predefined_macros_detect_operating_system] */
#if !defined(_WIN32) && (defined(__unix__) || defined(__unix)	\
		|| (defined(__APPLE__) && defined(__MACH__)))
#include <unistd.h>
#if defined(_POSIX_VERSION)
#define INCLUDE_SYSTIME_OK
#endif
#endif

/* Include sys/time.h header file if POSIX compatibility
   was determined, and use c++ ctime header file otherwise */
#ifdef INCLUDE_SYSTIME_OK
#include <sys/time.h>		/* C header file */
#else
#include <ctime.h>
#endif

#define PRIME_SIZE		1024	/* bits */
#define E_DEFAULT_VAL	65537

/************************* class RSA_Primes *************************
 *
 * RSA_Primes(void);
 *		Postcondition: Calls gen_primes function (See gen_primes function).
 *
 * void gen_primes(void);
 *		Postcondition: Generates two random primes values of PRIME_SIZE bits
 *			each, and then calculates their product and phi of their product.
 *
 * mpz_class get_prime_p(void) const;
 *		Postcondition: Returns first prime value (prime p).
 *
 * mpz_class get_prime_q(void) const;
 *		Postcondition: Returns second prime value (prime q).
 *
 * mpz_class get_n(void) const;
 *		Postcondition: Returns the product of the two prime values.
 *
 * mpz_class get_phi_of_n(void) const;
 *		Postcondition: Returns the result of phi of the product of the two
 *			prime values: phi(n) = (p - 1) * (q - 1).
 *
 ********************************************************************/

/************************* class RSA_PubKey *************************
 *
 * RSA_PubKey(void);
 *		Postcondition: Object data variables are set to default values.
 *
 * RSA_PubKey(RSA_Primes ppair);
 *		Postcondition: Calls gen_pair function (See gen_pair function).
 *
 * RSA_PubKey(mpz_class exp, mpz_class mod);
 *		Precondition: Same as set_pair function (See set_pair function).
 *		Postcondition: Calls set_pair function (See set_pair function).
 *			If set_pair function fails, then default values for data
 *			variables are set.
 *
 * void gen_pair(RSA_Primes ppair);
 *		Postcondition: The data values from ppair are used to generate a
 *			valid RSA public key.
 *
 * int set_pair(mpz_class exp, mpz_class mod);
 *		Precondition: exp and mod must be valid RSA public key exponent
 *			and modulus values corresponding to the same key.
 *		Postcondition: exp and mod are used as an RSA public key pair.
 *			Returns 0 upon success, and 1 upon failure.
 *
 * int encrypt(mpz_class &c, mpz_class m) const;
 *		Precondition: A valid RSA public key pair should already be set.
 *			m must be a positive integer less than than the modulus.
 *		Postcondition: m is encrypted using the RSA encryption algorithm,
 *			and stored in c. Returns 0 upon success, and 1 upon failure.
 *
 * void reset(void);
 *		Postcondition: Resets data variables to default values.
 *
 * mpz_class get_exp(void) const;
 *		Precondition: A valid RSA public key pair should already be set.
 *		Postcondition: Returns the RSA public exponent, e.
 *
 * mpz_class get_mod(void) const;
 *		Precondition: A valid RSA public key pair should already be set.
 *		Postcondition: Returns the RSA public modulus, n.
 *
 * bool is_valid(void) const;
 *		Postcondition: Returns true if a valid RSA public key pair is set,
 *			and false otherwise.
 *
 ********************************************************************/

/************************* class RSA_PrivKey *************************
 *
 * RSA_PrivKey(void);
 *		Postcondition: Object data variables are set to default values.
 *
 * RSA_PrivKey(RSA_Primes ppair, RSA_PubKey pub_k);
 *		Precondition: Same as gen_pair function (See gen_pair function).
 *		Postcondition: Calls gen_pair function (See gen_pair function).
 *			The object is not valid if neither the RSA private key pair,
 *			nor the Chinese Remainder Theorem (CRT) values are set, and
 *			the data variables will be set to their default values.
 *			However if the RSA private key pair is successfully generated
 *			and not the CRT values, then the key is still valid.
 *
 * RSA_PrivKey(mpz_class exp, mpz_class mod);
 *		Precondition: Same as set_pair function (See set_pair function).
 *		Postcondition: Calls set_pair function (See set_pair function).
 *			If set_pair function fails, then default values for data
 *			variables are set.
 *
 * RSA_PrivKey(mpz_class p, mpz_class q, mpz_class dp,
 *			   mpz_class dq, mpz_class qinv);
 *		Precondition: Same as set_crt_vals function (See set_crt_vals
 *			function).
 *		Postcondition: Calls set_crt_vals function (See set_crt_vals
 *			function).
 *
 * int gen_pair(RSA_Primes ppair, RSA_PubKey pub_k);
 *		Precondition: pub_k should be a valid RSA public key that was
 *			generated using the same values from ppair.
 *		Postcondition: Generates an RSA private key pair, and CRT values.
 *			Returns 0 if a complete key (key pair and CRT values) was
 *			generated, 1 if no key pair or CRT values were generated, and
 *			2 if only the key pair was generated.
 *
 * void set_crt_vals(mpz_class p, mpz_class q, mpz_class dp,
 *					 mpz_class dq, mpz_class qinv);
 *		Precondition: p, q, dp, dq, and qinv must be valid CRT values
 *			corresponding to the same RSA private key.
 *		Postcondition: CRT data variables are set to the value of their
 *			corresponding parameters.
 *
 * int decrypt(mpz_class &m, mpz_class c) const;
 *		Precondition: A valid RSA private key should already be set. c
 *			must be less than the modulus.
 *		Postcondition: c is decrypted using the RSA decryption algorithm
 *			if the CRT values are not set, and optimized using the Chinese
 *			Remainder Algorithm if they are set. The result is stored in
 *			m. Returns 0 upon success, and 1 upon failure.
 *
 * void reset(void);
 *		Postcondition: Resets data variables to default values.
 *
 * mpz_class get_prime_p(void) const;
 *		Precondition: CRT values should already be set.
 *		Postcondition: Returns the first prime value (prime p).
 *
 * mpz_class get_prime_q(void) const;
 *		Precondition: CRT values should already be set.
 *		Postcondition: Returns the second prime value (prime q).
 *
 * mpz_class get_crt_dp(void) const;
 *		Precondition: CRT values should already be set.
 *		Postcondition: Returns the CRT value, dp.
 *
 * mpz_class get_crt_dq(void) const;
 *		Precondition: CRT values should already be set.
 *		Postcondition: Returns the CRT value, dq.
 *
 * mpz_class get_crt_qinv(void) const;
 *		Precondition: CRT values should already be set.
 *		Postcondition: Returns the CRT value, qinv.
 *
 * bool is_valid(void) const;
 *		Postcondition: Returns true if a valid RSA private key pair is
 *			set or if CRT values are set, and false otherwise.
 *
 * bool has_pair(void) const;
 *		Postcondition: Returns true if a valid RSA private key pair is
 *			set, and false otherwise.
 *
 * bool has_crt_vals(void) const;
 *		Postcondition: Returns true if CRT values are set, and false
 *			otherwise.
 *
 * bool is_complete(void) const;
 *		Postcondition: Returns true if a valid RSA private key pair is
 *			set and the CRT value are set as well, and false otherwise.
 *
 *********************************************************************/

class RSA_Primes
{
	public:
		RSA_Primes(void);

		void		gen_primes(void);

		mpz_class	get_prime_p(void) const;
		mpz_class	get_prime_q(void) const;
		mpz_class	get_n(void) const;
		mpz_class	get_phi_of_n(void) const;

	private:
		mpz_class	m_p;
		mpz_class	m_q;

		mpz_class	m_n;	/* m_p * m_q */
		mpz_class	m_m;	/* phi of m_n */
};

class RSA_PubKey
{
	public:
		RSA_PubKey(void);
		RSA_PubKey(RSA_Primes ppair);
		RSA_PubKey(mpz_class exp, mpz_class mod);

		void		gen_pair(RSA_Primes ppair);
		int			set_pair(mpz_class exp, mpz_class mod);

		int			encrypt(mpz_class &c, mpz_class m) const;

		void		reset(void);

		mpz_class	get_exp(void) const;
		mpz_class	get_mod(void) const;

		bool		is_valid(void) const;

	protected:
		mpz_class	m_exp;
		mpz_class	m_mod;

		bool		m_pair_set;
};

class RSA_PrivKey: public RSA_PubKey
{
	public:
		RSA_PrivKey(void);
		RSA_PrivKey(RSA_Primes ppair, RSA_PubKey pub_k);
		RSA_PrivKey(mpz_class exp, mpz_class mod);
		RSA_PrivKey(mpz_class p, mpz_class q, mpz_class dp,
					mpz_class dq, mpz_class qinv);

		int			gen_pair(RSA_Primes ppair, RSA_PubKey pub_k);
		void		set_crt_vals(mpz_class p, mpz_class q, mpz_class dp,
								 mpz_class dq, mpz_class qinv);

		int			decrypt(mpz_class &m, mpz_class c) const;

		void		reset(void);

		mpz_class	get_prime_p(void) const;
		mpz_class	get_prime_q(void) const;

		mpz_class	get_crt_dp(void) const;
		mpz_class	get_crt_dq(void) const;
		mpz_class	get_crt_qinv(void) const;

		bool		is_valid(void) const;
		bool		has_pair(void) const;
		bool		has_crt_vals(void) const;
		bool		is_complete(void) const;

	private:
		mpz_class	m_p;
		mpz_class	m_q;

		// CRT (Chinese Remainder Theroem) values
		mpz_class	m_crt_dp;
		mpz_class	m_crt_dq;
		mpz_class	m_crt_qinv;

		bool		m_crt_set;
};

/**
 * Precondition: pub_k and priv_k must be valid RSA_PubKey
 *		and RSA_PrivKey objects.
 * Postcondition: pub_k and priv_k are initialized with valid
 *		RSA public and private key pairs.
 */
void RSA_gen_key_pairs(RSA_PubKey &pub_k, RSA_PrivKey &priv_k);

#endif		/* RSA_TB_H */
