#include "json.h"

using namespace rapidjson;
using namespace std;

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-08-18                                                      ///
/// @param[in]  obj_doc                 Json Document                           ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     true                    Find                                    ///
/// @retval     false                   Not Found                               ///
/// @desc       String Type의 Object 조회 API                                   ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_FindString(const Document &obj_doc, const char *pc_key)
{
    if (obj_doc.HasMember(pc_key) == false) {
        return false;
    }

    if (obj_doc[pc_key].IsString() == false) {
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-08-18                                                      ///
/// @param[in]  obj_json                Json Object                             ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     true                    Find                                    ///
/// @retval     false                   Not Found                               ///
/// @desc       String Type의 Object 조회 API                                   ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_FindString(const Value &obj_json, const char *pc_key)
{
    if (obj_json.HasMember(pc_key) == false) {
        return false;
    }

    if (obj_json[pc_key].IsString() == false) {
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-20                                                      ///
/// @param[in]  obj_doc                 Json Document                           ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     string                  String Value                            ///
/// @desc       String 획득 API                                                 ///
///////////////////////////////////////////////////////////////////////////////////
string Json_GetString(const Document &obj_doc, const char *pc_key)
{
    return obj_doc[pc_key].GetString();
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-20                                                      ///
/// @param[in]  obj_json                Json Object                             ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     nullptr                 Not Found Key or Not String Type        ///
/// @retval     string                  String Value                            ///
/// @desc       String 획득 API                                                 ///
///////////////////////////////////////////////////////////////////////////////////
string Json_GetString(const Value &obj_json, const char *pc_key)
{
    return obj_json[pc_key].GetString();
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-08-18                                                      ///
/// @param[in]  obj_doc                 Json Document                           ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     true                    Find                                    ///
/// @retval     false                   Not Found                               ///
/// @desc       Integer Type의 Object 조회 API                                  ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_FindInteger(const Document &obj_doc, const char *pc_key)
{
    if (obj_doc.HasMember(pc_key) == false) {
        return false;
    }

    if (obj_doc[pc_key].IsInt64() == false) {
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-08-18                                                      ///
/// @param[in]  obj_json                Json Object                             ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     true                    Find                                    ///
/// @retval     false                   Not Found                               ///
/// @desc       Integer Type의 Object 조회 API                                  ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_FindInteger(const Value &obj_json, const char *pc_key)
{
    if (obj_json.HasMember(pc_key) == false) {
        return false;
    }

    if (obj_json[pc_key].IsInt64() == false) {
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-20                                                      ///
/// @param[in]  obj_doc                 Json Document                           ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     Integer                 Unsigned Integer Value                  ///
/// @desc       Integer 획득 API                                                ///
///////////////////////////////////////////////////////////////////////////////////
uint64_t Json_GetInteger(const Document &obj_doc, const char *pc_key)
{
    return obj_doc[pc_key].GetInt64();
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-20                                                      ///
/// @param[in]  obj_json                Json Object                             ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     Integer                 Integer Value                           ///
/// @desc       Integer 획득 API                                                ///
///////////////////////////////////////////////////////////////////////////////////
uint64_t Json_GetInteger(const Value &obj_json, const char *pc_key)
{
    return obj_json[pc_key].GetInt64();
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-08-18                                                      ///
/// @param[in]  obj_doc                 Json Document                           ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     true                    Find                                    ///
/// @retval     false                   Not Found                               ///
/// @desc       Boolean Type의 Object 조회 API                                  ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_FindBoolean(const Document &obj_doc, const char *pc_key)
{
    if (obj_doc.HasMember(pc_key) == false) {
        return false;
    }

    if (obj_doc[pc_key].IsBool() == false) {
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-08-18                                                      ///
/// @param[in]  obj_json                Json Object                             ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     true                    Find                                    ///
/// @retval     false                   Not Found                               ///
/// @desc       Boolean Type의 Object 조회 API                                  ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_FindBoolean(const Value &obj_json, const char *pc_key)
{
    if (obj_json.HasMember(pc_key) == false) {
        return false;
    }

    if (obj_json[pc_key].IsBool() == false) {
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-20                                                      ///
/// @param[in]  obj_doc                 Json Document                           ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     Boolean                 Boolean Value                           ///
/// @desc       Boolean 획득 API                                                ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_GetBoolean(const Document &obj_doc, const char *pc_key)
{
    return obj_doc[pc_key].GetBool();
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-20                                                      ///
/// @param[in]  obj_json                Json Object                             ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     Boolean                 Boolean Value                           ///
/// @desc       Boolean 획득 API                                                ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_GetBoolean(const Value &obj_json, const char *pc_key)
{
    return obj_json[pc_key].GetBool();
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-08-18                                                      ///
/// @param[in]  obj_doc                 Json Document                           ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     true                    Find                                    ///
/// @retval     false                   Not Found                               ///
/// @desc       Object Type의 Object 조회 API                                   ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_FindObject(const Document &obj_doc, const char *pc_key)
{
    if (obj_doc.HasMember(pc_key) == false) {
        return false;
    }

    if (obj_doc[pc_key].IsObject() == false) {
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-08-18                                                      ///
/// @param[in]  obj_json                Json Object                             ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     true                    Find                                    ///
/// @retval     false                   Not Found                               ///
/// @desc       Object Type의 Object 조회 API                                   ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_FindObject(const Value &obj_json, const char *pc_key)
{
    if (obj_json.HasMember(pc_key) == false) {
        return false;
    }

    if (obj_json[pc_key].IsObject() == false) {
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-20                                                      ///
/// @param[in]  obj_doc                 Json Document                           ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     Object                  Object Value                            ///
/// @desc       Object 획득 API                                                 ///
///////////////////////////////////////////////////////////////////////////////////
Value &Json_GetObject(Document &obj_doc, const char *pc_key)
{
    return obj_doc[pc_key];
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-20                                                      ///
/// @param[in]  obj_json                Json Object                             ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     Object                  Object Value                            ///
/// @desc       Object 획득 API                                                 ///
///////////////////////////////////////////////////////////////////////////////////
Value &Json_GetObject(Value &obj_json, const char *pc_key)
{
    return obj_json[pc_key];
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-08-18                                                      ///
/// @param[in]  obj_doc                 Json Document                           ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     true                    Find                                    ///
/// @retval     false                   Not Found                               ///
/// @desc       Array Type의 Object 조회 API                                    ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_FindArray(const Document &obj_doc, const char *pc_key)
{
    if (obj_doc.HasMember(pc_key) == false) {
        return false;
    }

    if (obj_doc[pc_key].IsArray() == false) {
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-08-18                                                      ///
/// @param[in]  obj_json                Json Object                             ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     true                    Find                                    ///
/// @retval     false                   Not Found                               ///
/// @desc       Array Type의 Object 조회 API                                    ///
///////////////////////////////////////////////////////////////////////////////////
bool Json_FindArray(const Value &obj_json, const char *pc_key)
{
    if (obj_json.HasMember(pc_key) == false) {
        return false;
    }

    if (obj_json[pc_key].IsArray() == false) {
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-20                                                      ///
/// @param[in]  obj_doc                 Json Document                           ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     nullptr                 Not Found Key or Not Array Type         ///
/// @retval     Array                   Array Value                             ///
/// @desc       Array 획득 API                                                  ///
///////////////////////////////////////////////////////////////////////////////////
Value &Json_GetArray(Document &obj_doc, const char *pc_key)
{
    return obj_doc[pc_key];
}

///////////////////////////////////////////////////////////////////////////////////
/// @date       2020-07-20                                                      ///
/// @param[in]  obj_json                Json Object                             ///
/// @param[in]  pc_key                  Json Key                                ///
/// @retval     nullptr                 Not Found Key or Not Array Type         ///
/// @retval     Array                   Array Value                             ///
/// @desc       Array 획득 API                                                  ///
///////////////////////////////////////////////////////////////////////////////////
Value &Json_GetArray(Value &obj_json, const char *pc_key)
{
    return obj_json[pc_key];
}
