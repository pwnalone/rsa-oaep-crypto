/**
 * File: asn1_der_pem.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Implements the functions defined in asn1_der_pem.h header file.
 */

#include "asn1_der_pem.h"

int pem_pubkey_write(std::ofstream &file, RSA_PubKey pub_k)
{
	if (!file.is_open() || !pub_k.is_valid()) return 1;

	mpz_class		mod, exp;

	uint8_t			*main_tlv;
	size_t			main_bytes, main_val_bytes;
	uint8_t			*mod_tlv, *exp_tlv;
	size_t			mod_tlv_bytes, exp_tlv_bytes;

	size_t			k_start;
	std::string		pem_format_key;
	int				chars_left;

	// Get public key modulus and exponent integers
	mod = pub_k.get_mod();
	exp = pub_k.get_exp();

	// Convert integers into DER tlv pairs
	mod_tlv_bytes = put_tlv_int(&mod_tlv, mod);
	exp_tlv_bytes = put_tlv_int(&exp_tlv, exp);

	// Calculate number of bytes needed for entire DER encoding
	main_val_bytes = mod_tlv_bytes + exp_tlv_bytes;
	main_bytes = main_val_bytes + 1;
	main_bytes += (main_val_bytes < 128) ? 1 : (main_val_bytes < 256) ? 2 : 3;

	main_tlv = new uint8_t[main_bytes];
	main_tlv[0] = 0x30;						/* Sequence tag */

	/* Insert sequence length and find
	   sequence value start position */
	if (main_val_bytes < 128)
	{
		main_tlv[1] = main_val_bytes & 0xFF;
		k_start = 2;
	}
	else if (main_val_bytes < 256)
	{
		main_tlv[1] = 0x81;
		main_tlv[2] = main_val_bytes & 0xFF;
		k_start = 3;
	}
	else
	{
		main_tlv[1] = 0x82;
		main_tlv[2] = (main_val_bytes >> 8) & 0xFF;
		main_tlv[3] = main_val_bytes & 0xFF;
		k_start = 4;
	}

	// Insert DER tlv pairs (public key integers)
	memcpy(main_tlv + k_start, mod_tlv, mod_tlv_bytes);
	memcpy(main_tlv + k_start + mod_tlv_bytes, exp_tlv, exp_tlv_bytes);

	// Base64 encode DER-encoded public key
	base64_encode(pem_format_key, main_tlv, main_bytes);
	chars_left = pem_format_key.length();

	// Create DER PEM file out of encoded public key
	file << pem_pubkey_header << std::endl;

	/* Standard states that there should be 64
	   characters per line except for the last line */
	while (chars_left >= 64)
	{
		file << pem_format_key.substr(0, 64) << std::endl;
		pem_format_key.erase(0, 64);
		chars_left -= 64;
	}

	if (chars_left)
	{
		file << pem_format_key.substr(0, chars_left);
		file << std::endl;
	}

	file << pem_pubkey_footer << std::endl;
	file.close();

	// Free all allocated memory and ground pointers to NULL
	delete[] mod_tlv;
	delete[] exp_tlv;
	delete[] main_tlv;

	mod_tlv = NULL;
	exp_tlv = NULL;
	main_tlv = NULL;

	return 0;
}

int pem_pubkey_read(std::ifstream &file, RSA_PubKey &pub_k)
{
	if (!file.is_open()) return 1;

	std::string		header_line;
	std::string		footer_line;
	std::string		pem_format_key;
	std::string		tmp_str;

	uint8_t			*der_format_key;
	size_t			key_info_len;

	size_t			k_start;
	mpz_class		tmp_m, tmp_e;

	// First line must be correct header line for RSA public key
	std::getline(file, header_line);
	if (header_line != pem_pubkey_header) return 1;

	footer_line = "";
	pem_format_key = "";
	tmp_str = "";

	// Get the DER PEM encoded data from the file
	while (!file.eof())
	{
		std::getline(file, tmp_str);

		/* Stop reading from file when footer line
		   for RSA public key has been found */
		if (tmp_str == pem_pubkey_footer)
		{
			footer_line = tmp_str;
			break;
		}

		pem_format_key += tmp_str;
	}

	// Footer line for RSA public key must have been found
	if (footer_line != pem_pubkey_footer) return 1;

	// Decode base64-encoded data to get the DER-encoded data
	base64_decode(&der_format_key, key_info_len, pem_format_key);
	if (der_format_key[0] != 0x30)
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}

	// Find the start point of the public key integers
	if ((der_format_key[1] & (1 << 7)))
	{
		if ((der_format_key[1] & 0x7F) == 2) k_start = 4;
		else k_start = 3;
	}
	else k_start = 2;

	// Get integer values from DER tlv pairs
	if (!get_tlv_int_val(tmp_m, der_format_key, k_start))
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}
	if (!get_tlv_int_val(tmp_e, der_format_key, k_start))
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}

	// Free allocated memory and ground pointer to NULL
	delete[] der_format_key;
	der_format_key = NULL;

	/* Set the public key with the extracted
	   modulus and exponent integer values */
	if (pub_k.set_pair(tmp_e, tmp_m) == 1) return 1;
	file.close();

	return 0;
}

int pem_privkey_write(std::ofstream &file, RSA_PubKey pub_k, RSA_PrivKey priv_k)
{
	if (!file.is_open() || !priv_k.is_complete()) return 1;

	mpz_class		mod, priv_exp;
	mpz_class		pub_exp;
	mpz_class		p1, p2;
	mpz_class		dp, dq, qinv;

	uint8_t			*main_tlv;
	size_t			main_bytes, main_val_bytes;

	uint8_t			*mod_tlv, *priv_exp_tlv;
	size_t			mod_tlv_bytes, priv_exp_tlv_bytes;
	uint8_t			*pub_exp_tlv;
	size_t			pub_exp_tlv_bytes;

	uint8_t			*p1_tlv, *p2_tlv;
	size_t			p1_tlv_bytes, p2_tlv_bytes;
	uint8_t			*dp_tlv, *dq_tlv, *qinv_tlv;
	size_t			dp_tlv_bytes, dq_tlv_bytes, qinv_tlv_bytes;

	size_t			i_start;
	std::string		pem_format_key;
	int				chars_left;

	// Get private key integer values
	mod = priv_k.get_mod();
	priv_exp = priv_k.get_exp();
	pub_exp = pub_k.get_exp();

	p1 = priv_k.get_prime_p();
	p2 = priv_k.get_prime_q();

	dp = priv_k.get_crt_dp();
	dq = priv_k.get_crt_dq();
	qinv = priv_k.get_crt_qinv();

	// Convert integers into DER tlv pairs
	mod_tlv_bytes = put_tlv_int(&mod_tlv, mod);
	priv_exp_tlv_bytes = put_tlv_int(&priv_exp_tlv, priv_exp);
	pub_exp_tlv_bytes = put_tlv_int(&pub_exp_tlv, pub_exp);

	p1_tlv_bytes = put_tlv_int(&p1_tlv, p1);
	p2_tlv_bytes = put_tlv_int(&p2_tlv, p2);

	dp_tlv_bytes = put_tlv_int(&dp_tlv, dp);
	dq_tlv_bytes = put_tlv_int(&dq_tlv, dq);
	qinv_tlv_bytes = put_tlv_int(&qinv_tlv, qinv);

	// Calculate number of bytes needed for entire DER-encoded private key
	main_val_bytes = 3 + mod_tlv_bytes + priv_exp_tlv_bytes + pub_exp_tlv_bytes +
		p1_tlv_bytes + p2_tlv_bytes + dp_tlv_bytes + dq_tlv_bytes + qinv_tlv_bytes;

	main_bytes = main_val_bytes + 1;
	main_bytes += (main_val_bytes < 128) ? 1 : (main_val_bytes < 256) ? 2 : 3;

	main_tlv = new uint8_t[main_bytes];
	main_tlv[0] = 0x30;

	// Insert sequence length and find sequence value start position
	if (main_val_bytes < 128)
	{
		main_tlv[1] = main_val_bytes & 0xFF;
		i_start = 2;
	}
	else if (main_val_bytes < 256)
	{
		main_tlv[1] = 0x81;
		main_tlv[2] = main_val_bytes & 0xFF;
		i_start = 3;
	}
	else
	{
		main_tlv[1] = 0x82;
		main_tlv[2] = (main_val_bytes >> 8) & 0xFF;
		main_tlv[3] = main_val_bytes & 0xFF;
		i_start = 4;
	}

	// Insert version tlv (version: 0 - only two primes used)
	main_tlv[i_start++] = 0x02;
	main_tlv[i_start++] = 0x01;
	main_tlv[i_start++] = 0x00;

	// Insert DER tlv pairs (private key integers)
	memcpy(main_tlv + i_start, mod_tlv, mod_tlv_bytes);
	i_start += mod_tlv_bytes;
	memcpy(main_tlv + i_start, pub_exp_tlv, pub_exp_tlv_bytes);
	i_start += pub_exp_tlv_bytes;
	memcpy(main_tlv + i_start, priv_exp_tlv, priv_exp_tlv_bytes);
	i_start += priv_exp_tlv_bytes;

	memcpy(main_tlv + i_start, p1_tlv, p1_tlv_bytes);
	i_start += p1_tlv_bytes;
	memcpy(main_tlv + i_start, p2_tlv, p2_tlv_bytes);
	i_start += p2_tlv_bytes;

	memcpy(main_tlv + i_start, dp_tlv, dp_tlv_bytes);
	i_start += dp_tlv_bytes;
	memcpy(main_tlv + i_start, dq_tlv, dq_tlv_bytes);
	i_start += dq_tlv_bytes;
	memcpy(main_tlv + i_start, qinv_tlv, qinv_tlv_bytes);

	// Base64 encode DER-encoded public key
	base64_encode(pem_format_key, main_tlv, main_bytes);
	chars_left = pem_format_key.length();

	// Create DER PEM file out of encoded private key
	file << pem_privkey_header << std::endl;

	/* Standard states that there should be 64
	   characters per line except for the last line */
	while (chars_left >= 64)
	{
		file << pem_format_key.substr(0, 64) << std::endl;
		pem_format_key.erase(0, 64);
		chars_left -= 64;
	}

	if (chars_left)
	{
		file << pem_format_key.substr(0, chars_left);
		file << std::endl;
	}

	file << pem_privkey_footer << std::endl;
	file.close();

	// Free all allocated memory and ground pointers to NULL
	delete[] mod_tlv;
	delete[] priv_exp_tlv;
	delete[] pub_exp_tlv;
	delete[] p1_tlv;
	delete[] p2_tlv;
	delete[] dp_tlv;
	delete[] dq_tlv;
	delete[] qinv_tlv;
	delete[] main_tlv;

	mod_tlv = NULL;
	priv_exp_tlv = NULL;
	pub_exp_tlv = NULL;
	p1_tlv = NULL;
	p2_tlv = NULL;
	dp_tlv = NULL;
	dq_tlv = NULL;
	qinv_tlv = NULL;
	main_tlv = NULL;

	return 0;
}

int pem_privkey_read(std::ifstream &file, RSA_PrivKey &priv_k)
{
	if (!file.is_open()) return 1;

	std::string		header_line;
	std::string		pem_format_key;
	std::string		footer_line;
	std::string		tmp_str;

	uint8_t			*der_format_key;
	size_t			key_info_len;

	size_t			k_start;

	mpz_class		tmp_n, tmp_d, tmp_e;
	mpz_class		tmp_p, tmp_q;
	mpz_class		tmp_dp, tmp_dq, tmp_qinv;

	// First line must be correct header line for RSA private key
	std::getline(file, header_line);
	if (header_line != pem_privkey_header) return 1;

	footer_line = "";
	pem_format_key = "";
	tmp_str = "";

	// Get the DER PEM encoded data from the file
	while (!file.eof())
	{
		std::getline(file, tmp_str);

		/* Stop reading from file when footer line
		   for RSA private key has been found */
		if (tmp_str == pem_privkey_footer)
		{
			footer_line = tmp_str;
			break;
		}

		pem_format_key += tmp_str;
	}

	// Footer line for RSA private key must have been found
	if (footer_line != pem_privkey_footer) return 1;

	// Decode base64-encoded data to get the DER-encoded data
	base64_decode(&der_format_key, key_info_len, pem_format_key);
	if (der_format_key[0] != 0x30) return 1;

	// Find the start point of the public key integers
	if ((der_format_key[1] & (1 << 7)))
	{
		if ((der_format_key[1] & 0x7F) == 2) k_start = 4;
		else k_start = 3;
	}
	else k_start = 2;

	// Make sure version is correct (version = 0)
	if (der_format_key[k_start++] != 0x02)
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}
	if (der_format_key[k_start++] != 0x01)
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}
	if (der_format_key[k_start++] != 0x00)
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}

	// Get integer values from DER tlv pairs
	if (!get_tlv_int_val(tmp_n, der_format_key, k_start))
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}
	if (!get_tlv_int_val(tmp_e, der_format_key, k_start))
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}
	if (!get_tlv_int_val(tmp_d, der_format_key, k_start))
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}
	if (!get_tlv_int_val(tmp_p, der_format_key, k_start))
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}
	if (!get_tlv_int_val(tmp_q, der_format_key, k_start))
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}
	if (!get_tlv_int_val(tmp_dp, der_format_key, k_start))
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}
	if (!get_tlv_int_val(tmp_dq, der_format_key, k_start))
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}
	if (!get_tlv_int_val(tmp_qinv, der_format_key, k_start))
	{
		delete[] der_format_key;
		der_format_key = NULL;

		return 1;
	}

	// Free allocated memory and ground pointer to NULL
	delete[] der_format_key;
	der_format_key = NULL;

	// Set private key with extracted integer values
	if (priv_k.set_pair(tmp_d, tmp_n) == 1) return 1;
	priv_k.set_crt_vals(tmp_p, tmp_q, tmp_dp, tmp_dq, tmp_qinv);
	file.close();

	return 0;
}

/*** Helper functions */

size_t put_tlv_int(uint8_t **tlv, mpz_class mpi)
{
	size_t tlv_bytes, mpi_bytes;

	// Calculate minimum number of bytes needed to represent tlv value
	mpi_bytes = der_min_bytes(mpi);

	// Calculate total number of bytes needed for tlv pair
	tlv_bytes = mpi_bytes + 1;
	tlv_bytes += (mpi_bytes < 128) ? 1 : (mpi_bytes < 256) ? 2 : 3;
	
	*tlv = new uint8_t[tlv_bytes];
	(*tlv)[0] = 0x02;					/* Integer tag */

	// Insert tlv length and integer value into tlv pair
	if (mpi_bytes < 128)
	{
		(*tlv)[1] = mpi_bytes & 0xFF;
		I2OSP((*tlv) + 2, mpi, mpi_bytes);
	}
	else if (mpi_bytes < 256)
	{
		(*tlv)[1] = 0x81;
		(*tlv)[2] = mpi_bytes & 0xFF;
		I2OSP((*tlv) + 3, mpi, mpi_bytes);
	}
	else
	{
		(*tlv)[1] = 0x82;
		(*tlv)[2] = (mpi_bytes >> 8) & 0xFF;
		(*tlv)[3] = mpi_bytes & 0xFF;
		I2OSP((*tlv) + 4, mpi, mpi_bytes);
	}

	return tlv_bytes;		/* Total number of bytes */
}

bool get_tlv_int_val(mpz_class &i_val, uint8_t *der_block, size_t &tlv_start)
{
	// Tlv pair must have integer tag byte
	if (der_block[tlv_start] != 0x02) return false;

	size_t	val_start;
	size_t	val_len;

	// Find start and length of tlv integer value
	if ((der_block[tlv_start + 1] & (1 << 7)))
	{
		if ((der_block[tlv_start + 1] & 0x7F) == 2)
		{
			val_len = (der_block[tlv_start + 2] << 8) | (der_block[tlv_start + 3]);
			val_start = tlv_start + 4;
		}
		else
		{
			val_len = der_block[tlv_start + 2] & 0xFF;
			val_start = tlv_start + 3;
		}
	}
	else
	{
		val_len = der_block[tlv_start + 1];
		val_start = tlv_start + 2;
	}

	/* Convert tlv integer value to a multiple precision integer
	   and update tlv_start to next position of a tlv pair */
	OS2IP(i_val, der_block + val_start, val_len);
	tlv_start = val_start + val_len;

	return true;
}

size_t der_min_bytes(mpz_class mpi)
{
	size_t nbytes = 0;

	// Count number of bytes in an integer
	while (mpi > 256)
	{
		mpi /= 256;
		nbytes++;
	}

	/* Extra byte needed if most significant
	   bit of most significant byte is set */
	return (mpi >= 128) ? (nbytes + 2) : (nbytes + 1);
}
