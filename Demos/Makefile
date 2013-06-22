#
# Makefile
#
# Josh Inscoe
# 6/20/13
#

# Compiler and compiler flags to use
CC = g++
CFLAGS =

# Libraries needed (GMP library)
LIBS = -lgmpxx -lgmp

# Hash program files (source, header, object)
HASH_EXE = hash
HASH_SRCS = ../SHA256/sha256.cc hash.cc
HASH_HDRS = ../SHA256/sha256.h
HASH_OBJS = $(HASH_SRCS:.cc=.o)

# Target for hash program (source file: hash.cc)
$(HASH_EXE): $(HASH_OBJS) $(HASH_HDRS) Makefile
	$(CC) $(CFLAGS) $(HASH_OBJS) $(LIBS) -o $@ -I../SHA256/

# Dependencies for hash program
$(HASH_OBJS): $(HASH_HDRS) Makefile

# Mask program files (source, header, object)
MASK_EXE = mask
MASK_SRCS = ../Data_Conv/data_conv_prims.cc ../SHA256/sha256.cc ../MGF1/pkcs1_mgf1.cc mask.cc
MASK_HDRS = ../Data_Conv/data_conv_prims.h ../SHA256/sha256.h ../MGF1/pkcs1_mgf1.h
MASK_OBJS = $(MASK_SRCS:.cc=.o)

# Target for mask program (source file: mask.cc)
$(MASK_EXE): $(MASK_OBJS) $(MASK_HDRS) Makefile
	$(CC) $(CFLAGS) $(MASK_OBJS) $(LIBS) -o $@ -I../*/

# Dependencies for mask program
$(MASK_OBJS): $(MASK_HDRS) Makefile

# Oaep program files (source, header, object)
OAEP_EXE = oaep
OAEP_SRCS = ../Data_Conv/data_conv_prims.cc ../RSA/rsa_tb.cc ../DER_PEM/base64.cc ../DER_PEM/asn1_der_pem.cc ../SHA256/sha256.cc ../MGF1/pkcs1_mgf1.cc ../OAEP/pkcs1_eme_oaep_enc.cc ../OAEP/pkcs1_eme_oaep_dec.cc oaep.cc
OAEP_HDRS = ../Data_Conv/data_conv_prims.h ../RSA/rsa_tb.h ../DER_PEM/base64.h ../DER_PEM/asn1_der_pem.h ../SHA256/sha256.h ../MGF1/pkcs1_mgf1.h ../OAEP/pkcs1_eme_oaep_enc.h ../OAEP/pkcs1_eme_oaep_dec.h
OAEP_OBJS = $(OAEP_SRCS:.cc=.o)

# Target for oaep program (source file: oaep.cc)
$(OAEP_EXE): $(OAEP_OBJS) $(OAEP_HDRS) Makefile
	$(CC) $(CFLAGS) $(OAEP_OBJS) $(LIBS) -o $@ -I../*/

# Dependencies for oaep program
$(OAEP_OBJS): $(OAEP_HDRS) Makefile

# Target to remove any generated object files
clean:
	rm -f $(HASH_OBJS) $(MASK_OBJS) $(OAEP_OBJS) core
