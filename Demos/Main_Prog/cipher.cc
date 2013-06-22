/**
 * File: cipher.cc
 *
 * Programmer: Josh Inscoe
 * Date: 6/20/13
 *
 * Description:
 *		- Encrypts a user-inputted message, and allows user to specify a label to
 *			associate with the message (user must remember label).
 *		- Encrypts a random 128-bit AES key, and displays AES key to user.
 *		- Allows user to input a file name, and the program will create the file
 *			and store the produced cipher in that file.
 *		- Decrypts ciphers by allowing the user to input the cipher and the label
 *			associated with the cipher.
 *		- Decrypts ciphers stored in a file specified by the user.
 *		- Allows user to choose between displaying decrypted messages in ASCII or
 *			Hexadecimal format.
 *
 * Compile: make cipher
 */

#include <fstream>
#include <iostream>
#include <string>
#include <stdint.h>

#include "../../DER_PEM/asn1_der_pem.h"
#include "../../RSA_OAEP/rsa_oaep.h"

using namespace std;

// Enumerated values to represent RSA-OAEP operations
enum
{
	ENCRYPT = 1,
	DECRYPT = 2
};

// Enumerated values to represent encryption/decryption options
enum
{
	ENC_MSG = 1,
	ENC_AES = 2,
	DEC_INP = 3,
	DEC_FIL = 4
};

/**
 * Postcondition: Checks to see if RSA public/private key files exist
 *		in the ./.keys directory. If they do not, then a new RSA public/
 *		private key pair is created, and used to make these files.
 *		Returns true if files existed or were able to be created, and
 *		false otherwise.
 */
bool keyfiles_exist(void);

/**
 * Postcondition: Checks to see if the file by the name of file_nm exists.
 *		If it does, then the file is left open. Returns true if the file
 *		exists, and false otherwise.
 */
bool file_exists(ifstream &infile, string file_nm);

int main(void)
{
	RSA_OAEP		cipher;

	RSA_PubKey		pub_k;
	RSA_PrivKey		priv_k;

	ifstream		fpub_in;
	ifstream		fpriv_in;

	string			file_nm;
	ifstream		fciph_in;
	ofstream		fciph_out;

	int				op;

	string			msg_str;
	string			label_str;
	string			ciph_str;

	gmp_randclass	prng (gmp_randinit_default);
	mpz_class		sd, rand_aes;
	uint8_t			aes_key[16];		/* 128-bit AES key */

#ifdef INCLUDE_SYSTIME_OK
	struct timeval	t;
#else
	mpz_class		tmp_time;
#endif

	uint8_t			*M;
	size_t			mLen;
	mpz_class		C;

	// Make RSA public/private key files if they don't exist
	if (!keyfiles_exist())
	{
		cout << "Error: Failed to create RSA key files" << endl;
		return 1;
	}

	cout << "RSA-OAEP Primitives" << endl;
	cout << "-------------------" << endl;
	cout << "1) Encryption" << endl;
	cout << "2) Decryption" << endl;
	cout << endl;

	// Prompt user to select an RSA-OAEP operation
	cout << "Select Operation:\t";
	cin >> op;
	cin.ignore(1000, '\n');
	cout << endl;

	switch (op)
	{
		case ENCRYPT:
			// Open RSA public key file
			fpub_in.open(".keys/rsa_pub.pem");
			if (!fpub_in.is_open())
			{
				cout << "Error: Failed to open public key file" << endl;
				return 1;
			}

			// Read in RSA public key
			if (pem_pubkey_read(fpub_in, pub_k) == 1)
			{
				fpub_in.close();
				cout << "Error: Public key file corrupted" << endl;
				return 1;
			}

			cout << "RSA-OAEP Encryption" << endl;
			cout << "-------------------" << endl;
			cout << "1) Message" << endl;
			cout << "2) Random AES Key" << endl;
			cout << endl;

			// Prompt user for RSA-OAEP encryption option
			cout << "Select Option:\t";
			cin >> op;
			cin.ignore(1000, '\n');
			cout << endl;

			/* Prevent conflict with decryption options */
			if (op != 1 && op != 2) op = 0;

			break;

		case DECRYPT:
			// Open RSA private key file
			fpriv_in.open(".keys/rsa_priv.pem");
			if (!fpriv_in.is_open())
			{
				cout << "Error: Failed to open private key file" << endl;
				return 1;
			}

			// Read in RSA private key
			if (pem_privkey_read(fpriv_in, priv_k) == 1)
			{
				fpriv_in.close();
				cout << "Error: Private key file corrupted" << endl;
				return 1;
			}

			cout << "RSA-OAEP Decryption" << endl;
			cout << "-------------------" << endl;
			cout << "1) From Input" << endl;
			cout << "2) From File" << endl;
			cout << endl;

			// Prompt user for RSA-OAEP decryption option
			cout << "Select Option:\t";
			cin >> op;
			cin.ignore(1000, '\n');
			cout << endl;

			/* Prevent conflict with encryption options */
			if (op != 1 && op != 2) op = 0;
			else op += 2;

			break;

		default:
			// Display error and exit program if invalid operation chosen
			cout << "Error: Invalid operation " << op << endl;
			return 1;
	}

	switch (op)
	{
		case ENC_MSG:
			// Prompt user for message to encrypt
			cout << "Enter Message [Max 185 chars]:\t";
			getline(cin, msg_str);

			/* 185 char max because using 2048-bit (256 byte) keys,
			   which the max length is 190 chars more or less */
			if (msg_str.length() > 185)
			{
				cout << "Error: Message exceeds max length" << endl;
				return 1;
			}

			// Prompt user for message label (user will need to remember this)
			cout << "Enter Label:\t";
			getline(cin, label_str);
			cout << endl;

			// RSA-OAEP encrypt message and store in variable, C
			cipher.set_pubkey(pub_k);
			cipher.set_msg(msg_str);
			cipher.update_label(label_str);
			cipher.encrypt(C);
			cipher.clear();

			op = ENCRYPT;

			break;

		case ENC_AES:
#ifdef INCLUDE_SYSTIME_OK
			/* Using gettimeofday() rather than time() gives
			   a more random seed value for GMP prng */
			gettimeofday(&t, NULL);
			sd = t.tv_sec * t.tv_usec;
#else
			tmp_time = static_cast <unsigned int> (time(NULL));
			sd = tmp_time * tmp_time;
#endif

			// Seed GMP prng, and get a random 128-bit integer (AES key)
			prng.seed(sd);
			rand_aes = prng.get_z_bits(128);
			I2OSP(aes_key, rand_aes, 16);

			// Display AES key to user
			cout << "AES 128-bit key:\t" << rand_aes.get_str(16) << endl;
			cout << endl;

			// Encrypt random 128-bit AES key
			cipher.set_pubkey(pub_k);
			cipher.set_msg(aes_key, 16);
			cipher.encrypt(C);
			cipher.clear();

			op = ENCRYPT;

			break;

		case DEC_INP:
			// Prompt user for cipher (hex only)
			cout << "Enter Cipher [Hex format]:\t";
			cin >> ciph_str;
			cin.ignore(1000, '\n');
			cout << endl;

			// Set cipher value
			C.set_str(ciph_str, 16);

			// Prompt user for label (User should press ENTER if empty string)
			cout << "Enter Label [empty string for encrypted AES key]:\t";
			getline(cin, label_str);
			cout << endl;

			// Decrypt cipher
			cipher.set_privkey(priv_k);
			cipher.set_cipher(C);
			cipher.update_label(label_str);

			// Display error and exit program if decryption was unsuccessful
			if (cipher.decrypt(&M, mLen) != 0)
			{
				cout << "Error: Unsuccessful decryption of cipher" << endl;
				return 1;
			}

			cipher.clear();
			op = DECRYPT;
			
			break;

		case DEC_FIL:
			// Prompt user for name of file holding the cipher
			cout << "File with cipher [excluding file extension (.txt)]:\t";
			cin >> file_nm;
			cin.ignore(1000, '\n');

			file_nm += ".txt";

			// Open file containing the cipher
			fciph_in.open(file_nm.c_str());
			if (!fciph_in.is_open())
			{
				cout << endl;
				cout << "Error: Failed to open file containing cipher" << endl;
				return 1;
			}

			// Read the cipher from the file
			getline(fciph_in, ciph_str);
			fciph_in.close();

			// Set cipher value with read cipher
			C.set_str(ciph_str, 16);

			// Prompt user for label (User should press ENTER if empty string)
			cout << "Enter Label [empty string for encrypted AES key]:\t";
			getline(cin, label_str);
			cout << endl;

			// Decrypt cipher
			cipher.set_privkey(priv_k);
			cipher.set_cipher(C);
			cipher.update_label(label_str);

			// Display error and exit program if decryption was unsuccessful
			if (cipher.decrypt(&M, mLen) != 0)
			{
				cout << "Error: Unsuccessful decryption of cipher" << endl;
				return 1;
			}

			cipher.clear();
			op = DECRYPT;

			break;

		default:
			// Display error and exit if invalid option chosen
			cout << "Error: Invalid option " << op << endl;
			return 1;
	}

	// After encryption, write cipher to a file
	if (op == ENCRYPT)
	{
		// Prompt user for a file name
		cout << "File to store cipher:\t";
		cin >> file_nm;
		cout << endl;

		file_nm += ".txt";

		// Create a file by inputted file name
		fciph_out.open(file_nm.c_str());
		if (!fciph_out.is_open())
		{
			cout << "Error: Failed to open " << file_nm << " for writing" << endl;
			return 1;
		}

		// Write cipher to created file
		fciph_out << C.get_str(16) << endl;
		fciph_out.close();

		// Confirm that file was successfully created
		cout << file_nm << " successfully created!" << endl;
	}

	// After decryption, display message to the screen
	else
	{
		cout << "Message Format" << endl;
		cout << "--------------" << endl;
		cout << "1) ASCII" << endl;
		cout << "2) Hexadecimal" << endl;
		cout << endl;

		// Prompt user for a format to display decrypted message
		cout << "Select Format:\t";
		cin >> op;
		cout << endl;

		cout << "Decrypted Message:\t";

		// Display message as an ASCII string
		if (op == 1)
		{
			for (size_t i = 0; i < mLen; i++)
				cout << static_cast <char> (M[i]);
			cout << endl;
		}

		// Display message as a hexadecimal string
		else if (op == 2)
		{
			for (size_t i = 0; i < mLen; i++)
			{
				if (M[i] < 0x10) cout << "0";
				cout << hex << static_cast <unsigned int> (M[i]);
			}
			cout << endl;
		}

		/* Free memory allocated for decrypted
		   message and ground pointer to NULL */
		delete[] M;
		M = NULL;

		// If invalid display format was chosen, display error and exit program
		if (op != 1 && op != 2)
		{
			cout << "Error: Invalid option " << op << endl;
			return 1;
		}
	}

	return 0;
}

bool keyfiles_exist(void)
{
	RSA_PubKey		pub_k;
	RSA_PrivKey		priv_k;

	ifstream		fpub_in;
	ifstream		fpriv_in;
	ofstream		fpub_out;
	ofstream		fpriv_out;

	bool			file_missing = false;

	/* Both the RSA public key file and RSA private key file
	   must exist to be able to encrypt and decrypt a message */
	if (!file_exists(fpub_in, ".keys/rsa_pub.pem")) file_missing = true;
	else if (!file_exists(fpriv_in, ".keys/rsa_priv.pem"))
	{
		fpub_in.close();
		file_missing = true;
	}
	else
	{
		fpub_in.close();
		fpriv_in.close();
	}

	// Create the RSA public/private key files if either one didn't exist
	if (file_missing)
	{
		RSA_gen_key_pairs(pub_k, priv_k);

		// Write RSA public key to public key file
		fpub_out.open(".keys/rsa_pub.pem");
		if (!fpub_out.is_open()) return false;
		pem_pubkey_write(fpub_out, pub_k);

		// Write RSA private key to private key file
		fpriv_out.open(".keys/rsa_priv.pem");
		if (!fpriv_out.is_open()) return false;
		pem_privkey_write(fpriv_out, pub_k, priv_k);
	}

	return true;
}

bool file_exists(ifstream &infile, string file_nm)
{
	if (infile.is_open()) infile.close();

	// Keep file open if file exists
	infile.open(file_nm.c_str());
	return infile.is_open();
}
