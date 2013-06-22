/**
 * File: oaep.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/20/13
 *
 * Description:
 *		- Encodes an inputted (through the command line) message and label (if given),
 *			using the OAEP padding scheme, and displays encoded message to the screen.
 *		- Decodes the encoded message and displays the resulting message to the screen.
 *		- If the RSA public/private key files used for setting the key lengths are
 *			nonexistent, then they will be created.
 *
 * Compile: make oaep
 */

#include <fstream>
#include <iostream>
#include <string>
#include <stdint.h>

#include "../DER_PEM/asn1_der_pem.h"
#include "../OAEP/pkcs1_eme_oaep_enc.h"
#include "../OAEP/pkcs1_eme_oaep_dec.h"

using namespace std;

/**
 * Postcondition: Returns true if file by name of file_nm exists,
 *		and false otherwise. If file exists, then it is left open.
 */
bool file_exists(ifstream &file, string file_nm);

int main(int argc, const char *argv[])
{
	// Check for incorrect usage
	if (argc != 2 && argc != 3)
	{
		cout << "Usage: " << argv[0] << " ";
		cout << "message [label]" << endl;
		return 1;
	}

	RSA_PubKey			pub_k;
	RSA_PrivKey			priv_k;
	bool				keys_set = false;

	PKCS1_OAEP_Enc		enc_scheme;
	PKCS1_OAEP_Dec		dec_scheme;

	// Get the message and label from command line arguments
	string				msg = argv[1];
	string				label = (argc == 3) ? argv[2] : "";

	ifstream			infile;
	ofstream			outfile;

	uint8_t				*EM;
	size_t				EM_len;
	uint8_t				*M;
	size_t				mLen;

	// If the RSA public key file doesn't exists, then make one
	if (!file_exists(infile, ".keys/rsa_pub.pem"))
	{
		// Generate RSA public/private keys
		RSA_gen_key_pairs(pub_k, priv_k);
		keys_set = true;

		// Make sure file opens
		outfile.open(".keys/rsa_pub.pem");
		if (!outfile.is_open())
		{
			cout << "Error: Could not open rsa_pub.pem for writing";
			cout << endl;
			return 1;
		}

		// Write public key to file in DER-PEM format
		pem_pubkey_write(outfile, pub_k);
	}

	// Otherwise read public key from existing file
	else
	{
		// Exit program if public key file is corrupted
		if (pem_pubkey_read(infile, pub_k) == 1)
		{
			cout << "Error: RSA public key file has been corrupted";
			cout << endl;
			infile.close();

			return 1;
		}
	}

	// Perform OAEP padding scheme on message (with label)
	enc_scheme.set_key_len(pub_k);
	enc_scheme.set_msg(msg);
	enc_scheme.update_label(label);
	enc_scheme.encode();

	// Get the OAEP-encoded message
	EM_len = enc_scheme.get_key_len();
	EM = new uint8_t[EM_len];
	enc_scheme.get_enc_msg(EM);
	enc_scheme.clear_scheme();

	// Display OAEP-encoded message to the screen
	cout << "OAEP Encoded Message" << endl;
	cout << "--------------------" << endl;

	for (int i = 0; i < EM_len; i++)
	{
		if (EM[i] < 0x10) cout << "0";
		cout << hex << static_cast <unsigned int> (EM[i]);
	}
	cout << endl << endl;

	// If the RSA private key file doesn't exist, then make one
	if (!file_exists(infile, ".keys/rsa_priv.pem"))
	{
		/* If keys haven't already been generated */
		if (!keys_set) RSA_gen_key_pairs(pub_k, priv_k);

		// Make sure file opens
		outfile.open(".keys/rsa_priv.pem");
		if (!outfile.is_open())
		{
			cout << "Error: Could not open rsa_priv.pem for writing";
			cout << endl;

			delete[] EM;		/* Free memory before exiting program */
			EM = NULL;

			return 1;
		}

		// Write private key to file in DER-PEM format
		pem_privkey_write(outfile, pub_k, priv_k);
	}

	// Otherwise read private key from existing file
	else
	{
		// Exit program if private key file is corrupted
		if (pem_privkey_read(infile, priv_k) == 1)
		{
			cout << "Error: RSA private key file has been corrupted";
			cout << endl;
			infile.close();

			delete[] EM;
			EM = NULL;

			return 1;
		}
	}

	dec_scheme.set_key_len(priv_k);
	dec_scheme.set_enc_msg(EM, EM_len);
	dec_scheme.update_label(label);

	// If decoding was unsuccessful then exit program
	/* This might happen if one RSA key file existed,
	   while the other needed to be created */
	if (dec_scheme.decode() != 0)
	{
		cout << "Error: Failed to decode message" << endl;
		
		delete[] EM;
		EM = NULL;

		return 1;
	}

	// Get the decoded message
	mLen = dec_scheme.get_msg_len();
	M = new uint8_t[mLen];
	dec_scheme.get_msg(M);
	dec_scheme.clear_scheme();

	// Display the OAEP-decoded message to the screen
	cout << "Decoded Message:\t";

	for (int i = 0; i < mLen; i++)
		cout << static_cast <char> (M[i]);
	cout << endl;

	// Free all allocated memory and ground pointers to NULL
	delete[] EM;
	delete[] M;

	EM = NULL;
	M = NULL;

	return 0;
}

bool file_exists(ifstream &file, string file_nm)
{
	if (file.is_open()) file.close();

	// Keep file open if it exists
	file.open(file_nm.c_str());
	return file.is_open();
}
