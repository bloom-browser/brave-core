/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <openssl/base64.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <openssl/sha.h>

#include <random>
#include <iomanip>
#include <vector>

#include "base/base64.h"
#include "bat/ledger/internal/bat_helper.h"
#include "bat/ledger/internal/static_values.h"
#include "bat/ledger/internal/common/security_helper.h"

#include "tweetnacl.h"  // NOLINT

namespace braveledger_helper {

std::string Security::GetBase64(const std::vector<uint8_t>& data) {
  DCHECK_NE(data.size(), 0UL);
  size_t size = 0;
  if (!EVP_EncodedLength(&size, data.size())) {
    return "";
  }

  std::vector<uint8_t> string(size);
  int encoded_bytes_count =
      EVP_EncodeBlock(&string.front(), &data.front(), data.size());
  DCHECK_NE(encoded_bytes_count, 0);

  return std::string(reinterpret_cast<char*>(&string.front()));
}

std::vector<uint8_t> Security::GetSHA256(const std::string& string) {
  DCHECK(!string.empty());

  std::vector<uint8_t> string_sha256(SHA256_DIGEST_LENGTH);
  SHA256((uint8_t*)string.c_str(), string.length(), &string_sha256.front());
  return string_sha256;
}

std::string Security::Sign(
    const std::vector<std::map<std::string, std::string>>& headers,
    const std::string& key_id,
    const std::vector<uint8_t>& private_key) {
  DCHECK_NE(headers.size(), 0UL);
  DCHECK(!key_id.empty());
  DCHECK_NE(private_key.size(), 0UL);

  std::vector<std::string> header_keys;
  std::vector<std::string> header_values;

  for (const auto& header : headers) {
    const std::string key = header.begin()->first;
    const std::string value = header.begin()->second;

    header_keys.push_back(key);
    header_values.push_back(value);
  }

  std::vector<uint8_t> secret_key = GetHKDF(private_key);
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> new_secret_key;
  bool success = GetPublicKeyFromSeed(
      secret_key,
      &public_key,
      &new_secret_key);
  if (!success) {
    return "";
  }

  return braveledger_bat_helper::sign(
      header_keys,
      header_values,
      key_id,
      new_secret_key);
}

std::vector<uint8_t> Security::GenerateSeed() {
  std::vector<uint8_t> v_seed(SEED_LENGTH);
  std::random_device r;
  std::seed_seq seed{r(), r(), r(), r(), r(), r(), r(), r()};
  auto rand = std::bind(
      std::uniform_int_distribution<>(0, UCHAR_MAX),
      std::mt19937(seed));

  std::generate_n(v_seed.begin(), SEED_LENGTH, rand);
  return v_seed;
}

std::string Security::Uint8ToHex(const std::vector<uint8_t>& in) {
  std::ostringstream res;
  for (size_t i = 0; i < in.size(); i++) {
    res << std::setfill('0') << std::setw(sizeof(uint8_t) * 2)
       << std::hex << static_cast<int>(in[i]);
  }
  return res.str();
}

bool Security::GetPublicKeyFromSeed(
    const std::vector<uint8_t>& seed,
    std::vector<uint8_t>* public_key,
    std::vector<uint8_t>* secret_key) {
  DCHECK(public_key && secret_key && !seed.empty());
  if (seed.empty()) {
    return false;
  }

  public_key->resize(crypto_sign_PUBLICKEYBYTES);
  *secret_key = seed;
  secret_key->resize(crypto_sign_SECRETKEYBYTES);

  crypto_sign_keypair(&public_key->front(), &secret_key->front(), 1);

  DCHECK(!public_key->empty() && !secret_key->empty());
  if (public_key->empty() && secret_key->empty()) {
    return false;
  }

  return true;
}

std::vector<uint8_t> Security::GetHKDF(const std::vector<uint8_t>& seed) {
  DCHECK(!seed.empty());
  std::vector<uint8_t> out(SEED_LENGTH);

  const uint8_t info[] = {0};
  int hkdf_res = HKDF(
      &out.front(),
      SEED_LENGTH,
      EVP_sha512(),
      &seed.front(),
      seed.size(),
      braveledger_ledger::g_hkdfSalt,
      SALT_LENGTH,
      info,
      sizeof(info) / sizeof(info[0]));

  DCHECK(hkdf_res);
  DCHECK(!seed.empty());

  // We set the key_length to the length of the expected output and then take
  // the result from the first key, which is the client write key.

  return out;
}

}  // namespace braveledger_helper
