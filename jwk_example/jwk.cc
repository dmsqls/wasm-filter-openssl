#include "jwk.h"

using namespace std;
using namespace rapidjson;

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-05-14                                                      ///
/// @desc       JWK to Publick 변환                                             ///
///////////////////////////////////////////////////////////////////////////////////
namespace jwk 
{
///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       jose openssl Jwk를 Wasm에서 사용할 수 있도록 수정               ///
///////////////////////////////////////////////////////////////////////////////////
size_t Jwk::b64_dlen(size_t un_elen)
{
    switch (un_elen % B64_ENC_BLK) {
        case 0:
            return un_elen / B64_ENC_BLK * B64_DEC_BLK;
        case 2:
            return un_elen / B64_ENC_BLK * B64_DEC_BLK + 1;
        case 3:
            return un_elen / B64_ENC_BLK * B64_DEC_BLK + 2;
        default:
            break;
    }

    return SIZE_MAX;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       jose openssl Jwk를 Wasm에서 사용할 수 있도록 수정               ///
///////////////////////////////////////////////////////////////////////////////////
size_t Jwk::b64_dec_buf(const void *pv_i, size_t un_il, void *pv_o, size_t un_ol)
{
    const size_t len = strlen(b64_map);
    const char *e = (const char *)pv_i;
    uint8_t *d = (uint8_t *)pv_o;
    uint8_t rem = 0;
    size_t oo = 0;

    if (un_il == SIZE_MAX) {
        return SIZE_MAX;
    }

    if (pv_o == NULL) {
        return b64_dlen(un_il);
    }

    if (un_ol < b64_dlen(un_il)) {
        return SIZE_MAX;
    }

    for (size_t io = 0; io < un_il; io++) {
        uint8_t v = 0;

        for (const char c = e[io]; v < len && c != b64_map[v]; v++) {
            continue;
        }

        if (v >= len) {
            return SIZE_MAX;
        }

        switch (io % B64_ENC_BLK) {
            case 0:
                if ((e[io + 1] == 0x00) || (rem > 0)) {
                    return SIZE_MAX;
                }

                rem = v << 2;
                break;

            case 1:
                d[oo++] = rem | (v >> 4);
                rem = v << 4;
                break;

            case 2:
                d[oo++] = rem | (v >> 2);
                rem = v << 6;
                break;

            case 3:
                d[oo++] = rem | v;
                rem = 0;
                break;
        }
    }

    return (rem > 0) ? SIZE_MAX : oo;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       jose openssl Jwk를 Wasm에서 사용할 수 있도록 수정               ///
///////////////////////////////////////////////////////////////////////////////////
size_t Jwk::b64_dec(Value& obj_json, void *pv_o, size_t un_ol)
{
    StringBuffer str_tmp;
    Writer<StringBuffer> obj_writer(str_tmp);
    obj_json.Accept(obj_writer);

    string str_dump = str_tmp.GetString();
    if (str_dump.empty()) {
        return SIZE_MAX;
    }

    string str_json = str_dump.substr(1, str_dump.length() - 2);

    if (pv_o == NULL) {
        return b64_dlen(str_json.length());
    }

    return b64_dec_buf(str_json.c_str(), str_json.length(), pv_o, un_ol);
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       jose openssl Jwk를 Wasm에서 사용할 수 있도록 수정               ///
///////////////////////////////////////////////////////////////////////////////////
BIGNUM *Jwk::bn_decode(const uint8_t pun_buf[], size_t un_len)
{
    return BN_bin2bn(pun_buf, un_len, NULL);
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       jose openssl Jwk를 Wasm에서 사용할 수 있도록 수정               ///
///////////////////////////////////////////////////////////////////////////////////
BIGNUM *Jwk::bn_decode_json(Value& obj_json)
{
    uint8_t *pun_tmp = NULL;
    BIGNUM *pul_bn = NULL;
    size_t un_len = 0;

    un_len = b64_dec(obj_json, NULL, 0);
    if (un_len == SIZE_MAX) {
        return NULL;
    }

    pun_tmp = (uint8_t *)calloc(1, un_len);
    if (pun_tmp == NULL) {
        return NULL;
    }

    if (b64_dec(obj_json, pun_tmp, un_len) != un_len) {
        free(pun_tmp);
        return NULL;
    }

    pul_bn = bn_decode(pun_tmp, un_len);
    OPENSSL_cleanse(pun_tmp, un_len);
    free(pun_tmp);
    return pul_bn;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       jose openssl Jwk를 Wasm에서 사용할 수 있도록 수정               ///
///////////////////////////////////////////////////////////////////////////////////
EC_POINT *Jwk::mkpub(const EC_GROUP *pst_grp, Value& obj_x, Value& obj_y, const BIGNUM *pul_D)
{
    int n_ret = -1;
    EC_POINT *pst_pub = NULL, *pst_ret = NULL;
    BN_CTX *pst_ctx = NULL;
    BIGNUM *pul_x = NULL, *pul_y = NULL;

    if ((!obj_x.IsNull()) && (!obj_y.IsNull())) {
        pul_x = bn_decode_json(obj_x);
        pul_y = bn_decode_json(obj_y);
        pst_ctx = BN_CTX_new();
        pst_pub = EC_POINT_new(pst_grp);

        if ((pul_x != NULL) && (pul_y != NULL) && (pst_ctx != NULL) && (pst_pub != NULL)) {
            n_ret = EC_POINT_set_affine_coordinates_GFp(pst_grp, pst_pub, pul_x, pul_y, pst_ctx);
        }

        BN_free(pul_x);
        BN_free(pul_y);
        BN_CTX_free(pst_ctx);
    }
    else if (pul_D != NULL) {
        pst_ctx = BN_CTX_new();
        pst_pub = EC_POINT_new(pst_grp);

        if ((pst_ctx != NULL) && (pst_pub != NULL)) {
            n_ret = EC_POINT_mul(pst_grp, pst_pub, pul_D, NULL, NULL, pst_ctx);
        }

        BN_CTX_free(pst_ctx);
    }

    if (n_ret < 0) {
        EC_POINT_free(pst_pub);
        return NULL;
    }

    pst_ret = EC_POINT_dup(pst_pub, pst_grp);
    if (pst_ret == NULL) {
        EC_POINT_free(pst_pub);
    }

    return pst_ret;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       jose openssl Jwk를 Wasm에서 사용할 수 있도록 수정               ///
///////////////////////////////////////////////////////////////////////////////////
EC_KEY *Jwk::Jwk_to_EC_KEY(Document& obj_json)
{
    EC_POINT *pst_pub = NULL;
    EC_KEY *pst_key = NULL;
    BIGNUM *pul_D = NULL;
    string str_kty, str_crv;
    Value obj_x, obj_y, obj_d;
    int nid = NID_undef;

    if (!Json_FindString(obj_json, "kty")) {
        return NULL;
    }
    str_kty = Json_GetString(obj_json, "kty");
    if (str_kty != "EC") {
        return NULL;
    }

    if (!Json_FindString(obj_json, "crv")) {
        return NULL;
    }
    str_crv = Json_GetString(obj_json, "crv");

    if (str_crv == "P-256") {
        nid = NID_X9_62_prime256v1;
    }
    else if (str_crv == "P-384") {
        nid = NID_secp384r1;
    }
    else if (str_crv == "P-521") {
        nid = NID_secp521r1;
    }
    else {
        return NULL;
    }

    pst_key = EC_KEY_new_by_curve_name(nid);
    if (pst_key == NULL) {
        return NULL;
    }

    obj_x = Json_GetObject(obj_json, "x");
    obj_y = Json_GetObject(obj_json, "y");
    obj_d = Json_GetObject(obj_json, "d");

    if (!obj_d.IsNull()) {
        pul_D = bn_decode_json(obj_d);
        if (pul_D == NULL) {
            EC_KEY_free(pst_key);
            return NULL;
        }

        if (EC_KEY_set_private_key(pst_key, pul_D) < 0) {
            EC_KEY_free(pst_key);
            return NULL;
        }
    }

    pst_pub = mkpub(EC_KEY_get0_group(pst_key), obj_x, obj_y, pul_D);
    if (pst_pub == NULL) {
        EC_KEY_free(pst_key);
        return NULL;
    }

    if (EC_KEY_set_public_key(pst_key, pst_pub) < 0) {
        EC_KEY_free(pst_key);
        return NULL;
    }

    if (EC_KEY_check_key(pst_key) == 0) {
        EC_KEY_free(pst_key);
        return NULL;
    }

    if (EC_KEY_up_ref(pst_key) <= 0) {
        EC_KEY_free(pst_key);
        return NULL;
    }

    return pst_key;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       jose openssl Jwk를 Wasm에서 사용할 수 있도록 수정               ///
///////////////////////////////////////////////////////////////////////////////////
RSA *Jwk::Jwk_to_RSA(Document& obj_json)
{
    string str_kty;
    RSA *pst_rsa = NULL;
    Value obj_n, obj_e, obj_p, obj_q, obj_dp, obj_dq, obj_qi;
    BIGNUM *pul_n = NULL, *pul_e = NULL, *pul_p = NULL, *pul_q = NULL, *pul_dp = NULL, *pul_dq = NULL, *pul_qi = NULL;

    if (!Json_FindString(obj_json, "kty")) {
        return NULL;
    }
    str_kty = Json_GetString(obj_json, "kty");

    obj_n = Json_GetObject(obj_json, "n");
    if (obj_n.IsNull()) {
        return NULL;
    }

    obj_e = Json_GetObject(obj_json, "e");
    if (obj_e.IsNull()) {
        return NULL;
    }

    obj_p = Json_GetObject(obj_json, "p");
    obj_q = Json_GetObject(obj_json, "q");
    obj_dp = Json_GetObject(obj_json, "dp");
    obj_dq = Json_GetObject(obj_json, "dq");
    obj_qi = Json_GetObject(obj_json, "qi");

    pst_rsa = RSA_new();
    if (pst_rsa == NULL) {
        return NULL;
    }

    pul_n = bn_decode_json(obj_n);
    pul_e = bn_decode_json(obj_e);
    pul_p = bn_decode_json(obj_p);
    pul_q = bn_decode_json(obj_q);
    pul_dp = bn_decode_json(obj_dp);
    pul_dq = bn_decode_json(obj_dq);
    pul_qi = bn_decode_json(obj_qi);

    if ((obj_n.IsNull() || pul_n != NULL) && (obj_e.IsNull() || pul_e != NULL) && (obj_p.IsNull() || pul_p != NULL)
            && (obj_q.IsNull() || pul_q != NULL) && (obj_dp.IsNull() || pul_dp != NULL) && (obj_dq.IsNull() || pul_dq != NULL)
            && (obj_qi.IsNull() || pul_qi != NULL)) {

        if (RSA_set0_key(pst_rsa, pul_n, pul_e, NULL) > 0) {
            pul_n = NULL;
            pul_e = NULL;

            if (((pul_p == NULL) && (pul_q == NULL)) || (RSA_set0_factors(pst_rsa, pul_p, pul_q) > 0)) {
                pul_p = NULL;
                pul_q = NULL;

                if (((pul_dp == NULL) && (pul_dq == NULL) && (pul_qi == NULL)) || (RSA_set0_crt_params(pst_rsa, pul_dp, pul_dq, pul_qi) > 0)) {
                    pul_dp = NULL;
                    pul_dq = NULL;
                    pul_qi = NULL;

                    if (RSA_up_ref(pst_rsa) > 0) {
                        return pst_rsa;
                    }
                }
            }
        }
    }

    RSA_free(pst_rsa);
    BN_free(pul_n);
    BN_free(pul_e);
    BN_free(pul_p);
    BN_free(pul_q);
    BN_free(pul_dp);
    BN_free(pul_dq);
    BN_free(pul_qi);
    return NULL;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       jose openssl Jwk를 Wasm에서 사용할 수 있도록 수정               ///
///////////////////////////////////////////////////////////////////////////////////
EVP_PKEY *Jwk::Jwk_To_EVP_PKEY()
{
    EC_KEY *pst_ec = NULL;
    RSA *pst_rsa = NULL;
    EVP_PKEY *pst_public_key = NULL;

    string str_kty;
    uint8_t *pun_buf = NULL;
    size_t un_len = 0;

    Document obj_json;
    obj_json.Parse(str_jwk.c_str());
    if (obj_json.HasParseError()) {
        return NULL;
    }

    if (!Json_FindString(obj_json, "kty")) {
        return NULL;
    }
    str_kty = Json_GetString(obj_json, "kty");
    if (str_kty == "EC") {
        pst_ec = Jwk_to_EC_KEY(obj_json);
        if (pst_ec == NULL) {
            return NULL;
        }

        pst_public_key = EVP_PKEY_new();
        if (pst_public_key == NULL) {
            EC_KEY_free(pst_ec);
            return NULL;
        }

        if (EVP_PKEY_set1_EC_KEY(pst_public_key, pst_ec) > 0) {
            return pst_public_key;
        }

        EVP_PKEY_free(pst_public_key);
        return NULL;
    }
    else if (str_kty == "RSA") {
        pst_rsa = Jwk_to_RSA(obj_json);
        if (pst_rsa == NULL) {
            return NULL;
        }

        pst_public_key = EVP_PKEY_new();
        if (pst_public_key == NULL) {
            RSA_free(pst_rsa);
            return NULL;
        }

        if (EVP_PKEY_set1_RSA(pst_public_key, pst_rsa) > 0) {
            return pst_public_key;
        }

        EVP_PKEY_free(pst_public_key);
        return NULL;
    }
    else if (str_kty == "oct") {
        un_len = b64_dec(Json_GetObject(obj_json, "k"), NULL, 0);
        if (un_len == SIZE_MAX) {
            return NULL;
        }

        pun_buf = (uint8_t *)malloc(un_len);
        if (pun_buf == NULL) {
            return NULL;
        }

        if (b64_dec(Json_GetObject(obj_json, "k"), pun_buf, un_len) != un_len) {
            OPENSSL_cleanse(pun_buf, un_len);
            free(pun_buf);
            return NULL;
        }

        pst_public_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pun_buf, un_len);
        OPENSSL_cleanse(pun_buf, un_len);
        free(pun_buf);
        return pst_public_key;
    }

    return NULL;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       Jwk에서 Public Key 획득 API                                     ///
///////////////////////////////////////////////////////////////////////////////////
string Jwk::Get_Public_Key()
{
    char sz_public_key[MAX_PUBLIC_KEY] = "";

    EVP_PKEY *pst_key = Jwk_To_EVP_PKEY();

    /* public key를 추출 */
    BIO *pst_bp = BIO_new(BIO_s_mem());

    PEM_write_bio_PUBKEY(pst_bp, pst_key);
    BIO_read(pst_bp, sz_public_key, sizeof(sz_public_key));

    BIO_free(pst_bp);

    return string(sz_public_key);
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-13                                                      ///
/// @desc       Openssl Error 획득 API                                          ///
///////////////////////////////////////////////////////////////////////////////////
string Jwk::Get_Error()
{
    int n_line = 0;
    char sz_error_string[8192] = "";
    char *pc_file = NULL;
    string str_error;

    do {
        n_line = 0;
        pc_file = NULL;

        ERR_get_error_line((const char **)&pc_file, &n_line);
        if (pc_file == NULL) {
            break;
        }
        ERR_error_string(ERR_get_error(), sz_error_string);

        str_error += string(pc_file) + "/" + to_string(n_line) + " " + sz_error_string + "\n";
    } while (pc_file != NULL);

    return str_error;
}
} // namespace jwk 
