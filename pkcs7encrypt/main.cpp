#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#include <openssl\pem.h>
#include <openssl\x509.h>
#include <openssl\rsa.h>
#include <openssl\des.h>
#include <openssl\rand.h>
#include <openssl\pkcs7.h>
#include <openssl\applink.c>


int PasswordCallbackFromString(char *buf, int size, int rwflag, void *userdata)
{
	int length = strlen((char*)userdata);
	strncpy(buf, (char*)userdata, length);
	return length;
}

RSA* ReadPrivateKeyFromFile(char* path)
{
	RSA* rsa_wrapper = nullptr;
	FILE* fp = fopen(path, "r");
	if (fp == NULL)
	{
		printf("Can't find the key file");
		return nullptr;
	}
	BIO *bio = BIO_new(BIO_s_mem());
	unsigned char* buffer = (unsigned char*)malloc(40960);
	memset(buffer, 0, 40960);

	//read key from file in a buffer
	int key_length = fread(buffer, 1, 40960, fp);
	fclose(fp);

	//read bio from buffer into bio
	BIO_write(bio, buffer, key_length);

	//read RSA from bio
	PEM_read_bio_RSAPrivateKey(bio, &rsa_wrapper, 0, 0);
	//get them bits half_bits_ = BN_num_bits(n) / 2; //nah

	return rsa_wrapper;
}

RSA* ReadPublicKeyFromFile(char* path)
{
	RSA* rsa_wrapper = nullptr;
	FILE* fp = fopen(path, "r");
	BIO *bio = BIO_new(BIO_s_mem());
	unsigned char* buffer = (unsigned char*)malloc(40960);
	memset(buffer, 0, 40960);

	//read key from file in a buffer
	int key_length = fread(buffer, 1, 40960, fp);
	fclose(fp);

	//read bio from buffer into bio
	BIO_write(bio, buffer, key_length);
	//read RSA from bio
	PEM_read_bio_RSA_PUBKEY(bio, &rsa_wrapper, 0, 0);

	return rsa_wrapper;
}

X509* ReadCertificateFromFile(char* path) 
{
	FILE* fp = fopen(path, "rb");

	if (fp == NULL)
	{
		printf("Error loading certificate file ! \n");
		return NULL;
	}
	X509* certificate = X509_new();
	if (d2i_X509_fp(fp, &certificate) == NULL)
	{
		printf("Certificatul de intrare trebuie sa fie conform codarii BER ! \n");
		return nullptr;
	}
	fclose(fp);
	return certificate;
}

RSA*  GetPubKey(X509* certificate)
{
	EVP_PKEY * pubkey = X509_get_pubkey(certificate);

	RSA *public_key = RSA_new();
	public_key = EVP_PKEY_get1_RSA(pubkey);
	EVP_PKEY_free(pubkey);
	return public_key;
}

static int _read_from_file(char *filename, unsigned char **data, unsigned int *len)
{
	if (data == NULL || len == NULL)
		return 0;

	FILE *fp = fopen(filename, "rb");
	if (fp == NULL)
		return 0;

	fseek(fp, 0, SEEK_END);
	*len = (unsigned int)ftell(fp);
	fseek(fp, 0, SEEK_SET);

	*data = (unsigned char *)malloc(*len);

	fread(*data, 1, *len, fp);
	fclose(fp);

	return 1;
}

static int _write_to_file(char *filename, unsigned char *data, unsigned int len)
{
	if (data == NULL)
		return 0;

	FILE *fp = fopen(filename, "wb");
	if (fp == NULL)
		return 0;

	fwrite(data, 1, len, fp);

	fclose(fp);

	return 1;
}





int main(int argc, char** argv)
{
	//I LOVE this library...
	OPENSSL_add_all_algorithms_noconf();

	//Arguments processing
	if (argc != 6)
	{
		printf("Wrong syntax !\nEx: p7sign.exe file.in file.out u_cert.cer CA_cert.cer u_key.prv\n");
		return 1;
	}

	//reading data
	BIO* data_in = BIO_new(BIO_s_mem());
	BIO_read_filename(data_in, argv[1]);
	//reading signer's cert
	X509* signer_cert = ReadCertificateFromFile(argv[3]);
	//reading ca's cert
	X509* ca_cert = ReadCertificateFromFile(argv[4]);
	STACK_OF(X509)* certificates_stack = sk_X509_new_null();
	sk_X509_push(certificates_stack, ca_cert);
	//reading private key
	RSA* private_key = ReadPrivateKeyFromFile(argv[5]);
	//converting key to evp
	EVP_PKEY* evp_private_key = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(evp_private_key, private_key);
	//signing
	PKCS7* signed_data = PKCS7_sign(signer_cert, evp_private_key, certificates_stack, data_in, 0);
	//writing data
	BIO* data_out = BIO_new(BIO_s_mem());
	i2d_PKCS7_bio(data_out, signed_data);
	BIO_write_filename(data_out, argv[2]);
	return 0;
}