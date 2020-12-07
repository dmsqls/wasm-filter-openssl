#ifndef _JWK_H_
#define _JWK_H_

#include <string>
#include <map>
#include <set>
#include <pthread.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/objects.h>

#include "json.h"

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-05-14                                                      ///
///////////////////////////////////////////////////////////////////////////////////
namespace jwk 
{
#define MAX_PUBLIC_KEY                                  8192

#define B64_MAP "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
static const char *b64_map = B64_MAP;

#define B64_DEC_BLK 3
#define B64_ENC_BLK 4

class Jwk {
public:
    Jwk() {
        str_jwk.clear();
    }

    Jwk(std::string str_jwk) {
        this->str_jwk.clear();
        Set_Jwk(str_jwk);
    }

    ~Jwk() {}

    void Set_Jwk(std::string str_jwk) {
        this->str_jwk = str_jwk;
    };

    std::string Get_Public_Key();
    static std::string Get_Error();

private:
    size_t b64_dlen(size_t elen);
    size_t b64_dec_buf(const void *i, size_t il, void *o, size_t ol);
    size_t b64_dec(rapidjson::Value& obj_json, void *pv_o, size_t un_ol);
    BIGNUM *bn_decode(const uint8_t pun_buf[], size_t un_len);
    BIGNUM *bn_decode_json(rapidjson::Value& obj_json);
    EC_POINT *mkpub(const EC_GROUP *pst_grp, rapidjson::Value& obj_x, rapidjson::Value& obj_y, const BIGNUM *pul_D);

    EC_KEY *Jwk_to_EC_KEY(rapidjson::Document& obj_json);
    RSA *Jwk_to_RSA(rapidjson::Document& obj_json);
    EVP_PKEY *Jwk_To_EVP_PKEY();

    std::string str_jwk;
};
} // namespace jwk 
#endif
