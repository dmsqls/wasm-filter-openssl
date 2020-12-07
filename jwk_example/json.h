#ifndef _JSON_H_
#define _JSON_H_

#include <string>

#define NDEBUG

#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/writer.h"

bool Json_FindString(const rapidjson::Document &obj_doc, const char *pc_key);
bool Json_FindString(const rapidjson::Value &obj_json, const char *pc_key);
std::string Json_GetString(const rapidjson::Document &obj_doc, const char *pc_key);
std::string Json_GetString(const rapidjson::Value &obj_json, const char *pc_key);
bool Json_FindInteger(const rapidjson::Document &obj_doc, const char *pc_key);
bool Json_FindInteger(const rapidjson::Value &obj_json, const char *pc_key);
uint64_t Json_GetInteger(const rapidjson::Document &obj_doc, const char *pc_key);
uint64_t Json_GetInteger(const rapidjson::Value &obj_json, const char *pc_key);
bool Json_FindBoolean(const rapidjson::Document &obj_doc, const char *pc_key);
bool Json_FindBoolean(const rapidjson::Value &obj_json, const char *pc_key);
bool Json_GetBoolean(const rapidjson::Document &obj_doc, const char *pc_key);
bool Json_GetBoolean(const rapidjson::Value &obj_json, const char *pc_key);
bool Json_FindObject(const rapidjson::Document &obj_doc, const char *pc_key);
bool Json_FindObject(const rapidjson::Value &obj_json, const char *pc_key);
rapidjson::Value &Json_GetObject(rapidjson::Document &obj_doc, const char *pc_key);
rapidjson::Value &Json_GetObject(rapidjson::Value &obj_json, const char *pc_key);
bool Json_FindArray(const rapidjson::Document &obj_doc, const char *pc_key);
bool Json_FindArray(const rapidjson::Value &obj_json, const char *pc_key);
rapidjson::Value &Json_GetArray(rapidjson::Document &obj_doc, const char *pc_key);
rapidjson::Value &Json_GetArray(rapidjson::Value &obj_json, const char *pc_key);

#endif
