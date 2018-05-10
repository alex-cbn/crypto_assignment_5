#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#include <openssl\pem.h>
#include <openssl\x509.h>
#include <openssl\rsa.h>
#include <openssl\des.h>
#include <openssl\rand.h>
#include <openssl\pkcs7.h>


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

RSA*  getPubKey(char* cert_filename)
{

	FILE* fp = fopen(cert_filename, "rb");

	if (fp == NULL)
	{
		printf("Error loading certificate file ! \n");
		return NULL;
	}
	X509* cert = X509_new();
	d2i_X509_fp(fp, &cert);
	fclose(fp);

	EVP_PKEY * pubkey = X509_get_pubkey(cert);

	RSA *publicKey = RSA_new();
	publicKey = EVP_PKEY_get1_RSA(pubkey);
	EVP_PKEY_free(pubkey);
	X509_free(cert);
	return publicKey;
}

void _3des_encrypt(char* filename, unsigned char** outcipher, unsigned int *len, unsigned char** keys)
{
	unsigned char* input = NULL;
	int input_len = 0;
	_read_from_file(filename, &input, (unsigned int*)&input_len);

	int rest = (int)input_len % 8;
	unsigned char* infile = NULL;
	unsigned int infile_len = 0;
	if (rest == 0)
	{

		infile_len = input_len + 8;
		infile = (unsigned char *)malloc(infile_len);
		memcpy((void*)infile, (void*)input, input_len);
		free(input);
		for (int i = input_len; i < infile_len; i++)
			infile[i] = 0x08;
	}
	else
	{
		infile_len = input_len + 8 - rest;
		infile = (unsigned char *)malloc(infile_len);
		memcpy((void*)infile, (void*)input, input_len);
		free(input);
		rest = 8 - rest;
		for (int i = input_len; i < infile_len; i++)
			infile[i] = rest & 0x000000FF;

	}



	DES_cblock cb1;
	RAND_bytes(cb1, 8);
	DES_set_odd_parity(&cb1);

	DES_cblock cb2;
	RAND_bytes(cb2, 8);
	DES_set_odd_parity(&cb2);

	DES_cblock cb3;
	RAND_bytes(cb3, 8);
	DES_set_odd_parity(&cb3);


	DES_key_schedule k_schedule1, k_schedule2, k_schedule3;
	DES_set_key(&cb1, &k_schedule1);
	DES_set_key(&cb2, &k_schedule2);
	DES_set_key(&cb3, &k_schedule3);

	DES_cblock des_inblk;
	DES_cblock des_outblk;
	int blocksize = sizeof(DES_cblock);
	int offset = 0;
	unsigned char *output = NULL;
	output = (unsigned char*)malloc(infile_len);
	while (offset < infile_len)
	{
		memcpy(des_inblk, infile + offset, blocksize);
		DES_ecb3_encrypt(&des_inblk, &des_outblk, &k_schedule1, &k_schedule2, &k_schedule3, DES_ENCRYPT);
		memcpy(output + offset, des_outblk, blocksize);
		offset = offset + blocksize;
	}

	free(infile);
	unsigned char* deskeys = NULL;
	deskeys = (unsigned char*)malloc(24);
	unsigned char *p;
	memcpy((void*)deskeys, (void*)cb1, 8);

	p = deskeys + 8;
	memcpy((void*)p, (void*)cb2, 8);

	p = deskeys + 16;
	memcpy((void*)p, (void*)cb3, 8);

	*outcipher = output;
	*keys = deskeys;
	*len = infile_len;

}

int main(int argc, char** argv)
{
	// generarea unui certificat si o cheie privata pe baza unui certificat existent (modificarea public key) :

	//FILE* fp = fopen("ca-cert.der", "rb");

	//if (fp == NULL)
	//{
	//	printf("error");
	//	return 1;
	//}
	//X509* cert = X509_new();
	//d2i_X509_fp(fp, &cert);

	//RSA * rsakey = RSA_new();
	//BIGNUM *e = BN_new();
	//BN_dec2bn(&e, "3");
	//RSA_generate_key_ex(rsakey, 1024, e, NULL);

	//EVP_PKEY *a = EVP_PKEY_new();

	//EVP_PKEY_assign_RSA(a, rsakey);
	//X509_set_pubkey(cert, a);

	//FILE * fprv = fopen("key.prv", "wt");
	//PEM_write_RSAPrivateKey(fprv, rsakey, NULL, NULL, 0, NULL, NULL);
	//X509_sign(cert, a, EVP_sha1());
	//FILE *newcert = fopen("file.incert", "wb");
	//i2d_X509_fp(newcert, cert);

	//fclose(newcert);
	//fclose(fprv);
	//fclose(fp);


	if (argc != 4)
	{
		printf("Wrong syntax !\nEx: p7encrypt.exe file.indata file.incert file.out\n");
		return 1;
	}





	unsigned char* outCihper = NULL;
	unsigned int length = 0;
	unsigned char* des_keys = NULL;

	_3des_encrypt(argv[1], &outCihper, &length, &des_keys);



	FILE* fp = fopen(argv[2], "rb");

	if (fp == NULL)
	{
		printf("Error loading certificate file ! \n");
		return NULL;
	}
	X509* cert = X509_new();
	if (d2i_X509_fp(fp, &cert) == NULL)
	{
		printf("Certificatul de intrare trebuie sa fie conform codarii BER ! \n");
		return 2;

	}
	fclose(fp);



	RSA* publickey = NULL;
	publickey = getPubKey(argv[2]);

	ASN1_INTEGER * integ = ASN1_INTEGER_new();
	integ = BN_to_ASN1_INTEGER(publickey->n, integ);
	int cipherSize = integ->length;
	ASN1_INTEGER_free(integ);

	unsigned char* cipherKeys = NULL;
	cipherKeys = (unsigned char*)malloc(cipherSize);
	int padding = RSA_PKCS1_PADDING;
	RSA_public_encrypt(24, des_keys, cipherKeys, publickey, padding);
	free(des_keys);

	PKCS7_ENVELOPE* enveloped_data = PKCS7_ENVELOPE_new();


	enveloped_data->version->data = 0;
	PKCS7_RECIP_INFO* recipientInfo = PKCS7_RECIP_INFO_new();
	long ver = 4;

	ASN1_INTEGER_set(recipientInfo->version, ver);





	recipientInfo->cert = cert;


	recipientInfo->issuer_and_serial->issuer = cert->cert_info->issuer;
	recipientInfo->issuer_and_serial->serial = cert->cert_info->serialNumber;

	ASN1_BIT_STRING * encryptedkey = ASN1_BIT_STRING_new();
	ASN1_BIT_STRING_set(encryptedkey, cipherKeys, cipherSize);
	recipientInfo->enc_key = encryptedkey;



	recipientInfo->key_enc_algor->algorithm = OBJ_nid2obj(NID_rsaEncryption);


	sk_PKCS7_RECIP_INFO_push(enveloped_data->recipientinfo, recipientInfo);

	enveloped_data->enc_data = PKCS7_ENC_CONTENT_new();
	enveloped_data->enc_data->algorithm->algorithm = OBJ_nid2obj(NID_des_ecb);
	enveloped_data->enc_data->cipher = EVP_des_ecb();
	enveloped_data->enc_data->content_type = OBJ_nid2obj(NID_textNotice);
	ASN1_OCTET_STRING* octString = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(octString, outCihper, length);
	enveloped_data->enc_data->enc_data = octString;

	unsigned char* tofile = NULL;
	unsigned int l = 0;

	l = i2d_PKCS7_ENVELOPE(enveloped_data, &tofile);
	_write_to_file(argv[3], tofile, l);






	return 0;
}