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
#include <openssl\err.h>


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

RSA* GetPubKey(X509* certificate)
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
	ERR_load_CRYPTO_strings();
	OPENSSL_add_all_algorithms_noconf();

	//Arguments processing
	if (argc != 5)
	{
		printf("Wrong syntax !\nEx: p7verify.exe file.in signature.in u_cert.cer CA_cert.cer\n");
		return 1;
	}

	//reading original data
	unsigned int original_length = 0;
	unsigned char* original_data = 0;
	_read_from_file(argv[1], &original_data, &original_length);

	BIO* data_original = BIO_new(BIO_s_mem());
	BIO_write(data_original, original_data, original_length);

	//reading signature data
	unsigned int signature_length = 0;
	unsigned char* signature_data = 0;
	_read_from_file(argv[2], &signature_data, &signature_length);

	BIO* data_signature = BIO_new(BIO_s_mem());
	BIO_write(data_signature, signature_data, signature_length);

	PKCS7* signature_p7 = PKCS7_new();
	d2i_PKCS7_bio(data_signature, &signature_p7);

	//reading signer's cert
	X509* signer_cert = ReadCertificateFromFile(argv[3]);
	STACK_OF(X509)* certificates_stack = sk_X509_new_null();
	sk_X509_push(certificates_stack, signer_cert);

	//reading ca's cert and building the store
	X509* ca_cert = ReadCertificateFromFile(argv[4]);
	X509_STORE *s = X509_STORE_new();
	X509_STORE_add_cert(s, ca_cert);

	//verfiying certs

	//extracting public key
	RSA* public_key = GetPubKey(signer_cert);

	BIO* outie = BIO_new(BIO_s_mem());
	int status = PKCS7_verify(signature_p7, certificates_stack, s, data_signature, outie, PKCS7_NOVERIFY);
	unsigned int err = ERR_get_error();
	char* b = ERR_error_string(err, NULL);
	const char* a = ERR_reason_error_string(ERR_GET_REASON(err));

	ERR_print_errors_fp(stdout);
	//hasing the file
	//identifying algorithm 
	//decrypting message digest
	//extracting message digest
	//compare
	

	return 0;
}