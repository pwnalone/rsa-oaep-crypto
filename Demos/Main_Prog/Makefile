#
# Makefile
#
# Josh Inscoe
# 6/20/13
#

# Compiler and compiler flags to use
CC = g++
CFLAGS =

# Name of executable and necessary libraries (GMP library)
EXE = cipher
LIBS = -lgmpxx -lgmp

# List of source code files
SRCS = ../../Data_Conv/data_conv_prims.cc ../../DER_PEM/base64.cc ../../DER_PEM/asn1_der_pem.cc ../../RSA/rsa_tb.cc ../../SHA256/sha256.cc ../../MGF1/pkcs1_mgf1.cc ../../OAEP/pkcs1_eme_oaep_enc.cc ../../OAEP/pkcs1_eme_oaep_dec.cc ../../RSA_OAEP/rsa_oaep.cc cipher.cc

# List of header files
HDRS = ../../Data_Conv/data_conv_prims.h ../../DER_PEM/base64.h ../../DER_PEM/asn1_der_pem.h ../../RSA/rsa_tb.h ../../SHA256/sha256.h ../../MGF1/pkcs1_mgf1.h ../../OAEP/pkcs1_eme_oaep_enc.h ../../OAEP/pkcs1_eme_oaep_dec.h ../../RSA_OAEP/rsa_oaep.h

# Automatically generated list of object files
OBJS = $(SRCS:.cc=.o)

# Default target
$(EXE): $(OBJS) $(HDRS) Makefile
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $@ -I../../*/

# Dependencies
$(OBJS): $(HDRS) Makefile

# Target to remove all generated object files
clean:
	rm -f $(OBJS) core
