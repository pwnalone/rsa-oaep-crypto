/**
 * File: asn1_der_pem.h
 *
 * Programmer: Josh Inscoe
 * Date: 6/19/13
 *
 * Description:
 *		- Defines functions for reading/writing DER-PEM encoded RSA public and
 *			private keys to files.
 */

#ifndef ASN1_DER_PEM_H
#define ASN1_DER_PEM_H

#include <fstream>
#include <string>

#include "../Data_Conv/data_conv_prims.h"
#include "../RSA/rsa_tb.h"
#include "base64.h"

const std::string pem_pubkey_header = "-----BEGIN RSA PUBLIC KEY-----";
const std::string pem_pubkey_footer = "-----END RSA PUBLIC KEY-----";
const std::string pem_privkey_header = "-----BEGIN RSA PRIVATE KEY-----";
const std::string pem_privkey_footer = "-----END RSA PRIVATE KEY-----";

/**
 * Precondition: file must be open and pub_k must be a valid RSA public key.
 * Postcondition: pub_k data is written to file in DER PEM format. Returns 0
 *		upon success, and 1 upon failure.
 */
int		pem_pubkey_write(std::ofstream &file, RSA_PubKey pub_k);

/**
 * Precondition: file must be open and must contain a DER PEM formatted RSA
 *		public key.
 * Postcondition: RSA public key data is extracted from file, and stored in
 *		pub_k to create a valid RSA public key. Returns 0 upon succes, and 1
 *		upon failure.
 */
int		pem_pubkey_read(std::ifstream &file, RSA_PubKey &pub_k);

/**
 * Precondition: file must be open and priv_k must be a valid and complete
 *		(containing CRT values too) RSA private key.
 * Postcondition: priv_k data is written to file in DER PEM format. Returns
 *		0 upon success, and 1 upon failure.
 */
int		pem_privkey_write(std::ofstream &file, RSA_PubKey pub_k, RSA_PrivKey priv_k);

/**
 * Precondition: file must be open and must contain a DER PEM formatted RSA
 *		private key.
 * Postcondition: RSA private key data is extracted from file, and stored in
 *		priv_k to create a valid RSA public key. Returns 0 upon success, and
 *		1 upon failure.
 */
int		pem_privkey_read(std::ifstream &file, RSA_PrivKey &priv_k);

/*** Helper functions */

/**
 * Precondition: mpi must be positive.
 * Postcondition: Memory is allocated to store a DER tlv integer pair in *tlv.
 *		mpi is used as the value for the tlv pair. Returns the number of
 *		indices in *tlv.
 */
size_t	put_tlv_int(uint8_t **tlv, mpz_class mpi);

/**
 * Precondition: der_block must contain DER encoded data and tlv_start must be
 *		the index of the start of a DER tlv integer pair.
 * Postcondition: The value of the DER tlv integer pair is extracted and stored
 *		in i_val. Returns true upon success, and false upon failure.
 */
bool	get_tlv_int_val(mpz_class &i_val, uint8_t *der_block, size_t &tlv_start);

/**
 * Precondition: mpi is positive.
 * Postcondition: Returns the minimum number of bytes needed to store the value
 *		of mpi in a DER tlv integer pair.
 */
size_t	der_min_bytes(mpz_class mpi);

#endif		/* ASN1_DER_PEM_H */
