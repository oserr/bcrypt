#include <string>
#include <cstring>
#include <vector>
#include <stdlib.h>

#include "bcrypt.h"

namespace bcrypt {

bool ValidateSalt(const char* salt);

/* SALT GENERATION */

std::string GenSalt(uint8_t rounds = 10, char minor = 'b');

/* ENCRYPT DATA - USED TO BE HASHPW */

std::string Encrypt(const Napi::CallbackInfo& info);

bool Compare(const Napi::CallbackInfo& info);

uint8_t GetRounds(const Napi::CallbackInfo& info);

} // namespace bcrypt
