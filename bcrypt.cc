#include <string>
#include <cstring>
#include <vector>
#include <stdlib.h> // atoi

#include "bcrypt.h"

namespace bcrypt {

inline char ToCharVersion(const std::string& str) {
  return str[0];
}

bool ValidateSalt(const char* salt) {
  if (!salt || *salt != '$') {
    return false;
  }
  
  // discard $
  salt++;
  
  if (*salt > BCRYPT_VERSION) {
    return false;
  }
  
  if (salt[1] != '$') {
    switch (salt[1]) {
    case 'a':
    case 'b':
      salt++;
      break;
    default:
      return false;
    }
  }
  
  // discard version + $
  salt += 2;
  
  if (salt[2] != '$') {
    return false;
  }
  
  int n = atoi(salt);
  if (n > 31 || n < 0) {
    return false;
  }
  
  if (((uint8_t)1 << (uint8_t)n) < BCRYPT_MINROUNDS) {
    return false;
  }
  
  salt += 3;
  if (strlen(salt) * 3 / 4 < BCRYPT_MAXSALT) {
    return false;
  }
  
  return true;
}

/* SALT GENERATION */

std::string GenSalt(uint8_t rounds = 10, char minor = 'b') {
  u_int8_t* seed = (u_int8_t*) buffer.Data();
  char salt[_SALT_LEN];
  bcrypt_gensalt(minor_ver, rounds, seed, salt);
  return Napi::String::New(env, salt, strlen(salt));
}

/* ENCRYPT DATA - USED TO BE HASHPW */

std::string Encrypt(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
      throw Napi::TypeError::New(info.Env(), "2 arguments expected");
  }
  std::string data = info[0].IsBuffer()
      ? BufferToString(info[0].As<Napi::Buffer<char>>())
      : info[0].As<Napi::String>();
  std::string salt = info[1].As<Napi::String>();
  if (!(ValidateSalt(salt.c_str()))) {
      throw Napi::Error::New(env, "Invalid salt. Salt must be in the form of: $Vers$log2(NumRounds)$saltvalue");
  }
  char bcrypted[_PASSWORD_LEN];
  bcrypt(data.c_str(), data.length(), salt.c_str(), bcrypted);
  return Napi::String::New(env, bcrypted, strlen(bcrypted));
}

/* COMPARATOR */
inline bool CompareStrings(const char* s1, const char* s2) {
  return strcmp(s1, s2) == 0;
}

bool Compare(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
      throw Napi::TypeError::New(info.Env(), "2 arguments expected");
  }
  std::string pw = info[0].IsBuffer()
      ? BufferToString(info[0].As<Napi::Buffer<char>>())
      : info[0].As<Napi::String>();
  std::string hash = info[1].As<Napi::String>();
  char bcrypted[_PASSWORD_LEN];
  if (ValidateSalt(hash.c_str())) {
      bcrypt(pw.c_str(), pw.length(), hash.c_str(), bcrypted);
      return Napi::Boolean::New(env, CompareStrings(bcrypted, hash.c_str()));
  } else {
      return Napi::Boolean::New(env, false);
  }
}

uint8_t GetRounds(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
      throw Napi::TypeError::New(env, "1 argument expected");
  }
  std::string hash =  info[0].As<Napi::String>();
  u_int32_t rounds;
  if (!(rounds = bcrypt_get_rounds(hash.c_str()))) {
      throw Napi::Error::New(env, "invalid hash provided");
  }
  return Napi::Number::New(env, rounds);
}

} // namespace bcrypt
