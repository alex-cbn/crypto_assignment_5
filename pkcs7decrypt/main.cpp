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
static void _print_hexa_buffer(unsigned char *buffer, unsigned int len)
{
	int i;

	fprintf(stdout, "\n");
	for (i = 0; i < (int)len; i++)
		fprintf(stdout, "%02X ", buffer[i]);

	fprintf(stdout, "\n");
}

int main(int argc, char**argv)
{


	if (argc != 4)
	{
		printf("Wrong syntax !\nEx: p7encrypt.exe file.data file.privkey file.out\n");
		return 1;
	}

	unsigned char* envelope = NULL;
	unsigned int env_len = 0;
	PKCS7_ENVELOPE* env = PKCS7_ENVELOPE_new();
	_read_from_file(argv[1], &envelope, &env_len);
	env = d2i_PKCS7_ENVELOPE(&env, (const unsigned char**)&envelope, env_len);

	PKCS7_RECIP_INFO* repinfo = PKCS7_RECIP_INFO_new();
	repinfo = sk_PKCS7_RECIP_INFO_pop(env->recipientinfo);

	unsigned char* cryptedKeys = NULL;
	unsigned int len = 0;
	len = repinfo->enc_key->length;
	cryptedKeys = (unsigned char*)malloc(len);
	memcpy(cryptedKeys, repinfo->enc_key->data, len);

	FILE* prvkey = fopen(argv[2], "rb");
	RSA* rsaprvkey = RSA_new();
	PEM_read_RSAPrivateKey(prvkey, &rsaprvkey, NULL, NULL);
	fclose(prvkey);
	unsigned char * plainKeys = NULL;
	plainKeys = (unsigned char*)malloc(24);
	RSA_private_decrypt(len, cryptedKeys, plainKeys, rsaprvkey, RSA_PKCS1_PADDING);

	RSA_free(rsaprvkey);

	unsigned char* ciphertext = NULL;
	unsigned int ciph_len = 0;
	ciph_len = env->enc_data->enc_data->length;
	ciphertext = (unsigned char*)malloc(ciph_len);
	memcpy(ciphertext, env->enc_data->enc_data->data, ciph_len);

	DES_cblock cb1, cb2, cb3;
	memcpy(cb1, plainKeys, 8);
	unsigned char* p;
	p = plainKeys + 8;
	memcpy(cb2, p, 8);
	p = p + 8;
	memcpy(cb3, p, 8);

	DES_key_schedule k_schedule1, k_schedule2, k_schedule3;
	DES_set_key(&cb1, &k_schedule1);
	DES_set_key(&cb2, &k_schedule2);
	DES_set_key(&cb3, &k_schedule3);
	DES_cblock des_inblk;
	DES_cblock des_outblk;

	int blocksize = sizeof(DES_cblock);
	int offset = 0;
	unsigned char *output = NULL;
	output = (unsigned char*)malloc(ciph_len);
	while (offset < ciph_len)
	{
		memcpy(des_inblk, ciphertext + offset, blocksize);
		DES_ecb3_encrypt(&des_inblk, &des_outblk, &k_schedule1, &k_schedule2, &k_schedule3, DES_DECRYPT);
		memcpy(output + offset, des_outblk, blocksize);
		offset = offset + blocksize;
	}

	int padd = output[ciph_len - 1];
	_write_to_file(argv[3], output, ciph_len - padd);



	free(output);
	free(ciphertext);
	free(plainKeys);

	free(cryptedKeys);
	PKCS7_ENVELOPE_free(env);
	return 0;
}