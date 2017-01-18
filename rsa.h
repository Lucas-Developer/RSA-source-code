
#ifndef MBEDTLS_RSA_H
#define MBEDTLS_RSA_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "bignum.h"
#include "md.h"

#if defined(MBEDTLS_THREADING_C)
#include "threading.h"
#endif


#define MBEDTLS_ERR_RSA_BAD_INPUT_DATA                    -0x4080  
#define MBEDTLS_ERR_RSA_INVALID_PADDING                   -0x4100  
#define MBEDTLS_ERR_RSA_KEY_GEN_FAILED                    -0x4180  
#define MBEDTLS_ERR_RSA_KEY_CHECK_FAILED                  -0x4200  
#define MBEDTLS_ERR_RSA_PUBLIC_FAILED                     -0x4280  
#define MBEDTLS_ERR_RSA_PRIVATE_FAILED                    -0x4300  
#define MBEDTLS_ERR_RSA_VERIFY_FAILED                     -0x4380  
#define MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE                  -0x4400  
#define MBEDTLS_ERR_RSA_RNG_FAILED                        -0x4480  


#define MBEDTLS_RSA_PUBLIC      0
#define MBEDTLS_RSA_PRIVATE     1

#define MBEDTLS_RSA_PKCS_V15    0
#define MBEDTLS_RSA_PKCS_V21    1

#define MBEDTLS_RSA_SIGN        1
#define MBEDTLS_RSA_CRYPT       2

#define MBEDTLS_RSA_SALT_LEN_ANY    -1


#if defined(MBEDTLS_RSA_C)

#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
    int ver;                    
    size_t len;                 

    mbedtls_mpi N;                      
    mbedtls_mpi E;                      

    mbedtls_mpi D;                     
    mbedtls_mpi P;                      
    mbedtls_mpi Q;                      
    mbedtls_mpi DP;                    
    mbedtls_mpi DQ;                     
    mbedtls_mpi QP;                     

    mbedtls_mpi RN;                     
    mbedtls_mpi RP;                     
    mbedtls_mpi RQ;                    

    mbedtls_mpi Vi;                     
    mbedtls_mpi Vf;                     

    int padding;                
                                    
    int hash_id;                
                                      
                                      
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex;    
#endif
}
mbedtls_rsa_context;


void mbedtls_rsa_init( mbedtls_rsa_context *ctx,
               int padding,
               int hash_id);


void mbedtls_rsa_set_padding( mbedtls_rsa_context *ctx, int padding, int hash_id);


int mbedtls_rsa_gen_key( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent );


int mbedtls_rsa_check_pubkey( const mbedtls_rsa_context *ctx );


int mbedtls_rsa_check_privkey( const mbedtls_rsa_context *ctx );


int mbedtls_rsa_check_pub_priv( const mbedtls_rsa_context *pub, const mbedtls_rsa_context *prv );


int mbedtls_rsa_public( mbedtls_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output );


int mbedtls_rsa_private( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output );


int mbedtls_rsa_pkcs1_encrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t ilen,
                       const unsigned char *input,
                       unsigned char *output );


int mbedtls_rsa_rsaes_pkcs1_v15_encrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output );


int mbedtls_rsa_rsaes_oaep_encrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output );

int mbedtls_rsa_pkcs1_decrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len );


int mbedtls_rsa_rsaes_pkcs1_v15_decrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len );


int mbedtls_rsa_rsaes_oaep_decrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len );


int mbedtls_rsa_pkcs1_sign( mbedtls_rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    int mode,
                    mbedtls_md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig );


int mbedtls_rsa_rsassa_pkcs1_v15_sign( mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig );
 
int mbedtls_rsa_rsassa_pss_sign( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         int mode,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig );

            \c mbedtls_rsa_rsassa_pss_verify() about md_alg and hash_id.
 
int mbedtls_rsa_pkcs1_verify( mbedtls_rsa_context *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng,
                      int mode,
                      mbedtls_md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig );


int mbedtls_rsa_rsassa_pkcs1_v15_verify( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode,
                                 mbedtls_md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig );


int mbedtls_rsa_rsassa_pss_verify( mbedtls_rsa_context *ctx,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng,
                           int mode,
                           mbedtls_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig );


int mbedtls_rsa_rsassa_pss_verify_ext( mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               mbedtls_md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig );


int mbedtls_rsa_copy( mbedtls_rsa_context *dst, const mbedtls_rsa_context *src );


void mbedtls_rsa_free( mbedtls_rsa_context *ctx );


int mbedtls_rsa_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif 

#endif 