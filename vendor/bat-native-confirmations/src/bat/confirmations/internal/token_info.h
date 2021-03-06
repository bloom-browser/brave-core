/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BAT_CONFIRMATIONS_INTERNAL_TOKEN_INFO_H_
#define BAT_CONFIRMATIONS_INTERNAL_TOKEN_INFO_H_

#include <string>
#include <vector>

#include "wrapper.hpp"  // NOLINT

namespace confirmations {

using challenge_bypass_ristretto::UnblindedToken;

struct TokenInfo {
  TokenInfo();
  TokenInfo(
      const TokenInfo& info);
  ~TokenInfo();

  bool operator==(
      const TokenInfo& rhs) const;
  bool operator!=(
      const TokenInfo& rhs) const;

  UnblindedToken unblinded_token;
  std::string public_key;
};

using TokenList = std::vector<TokenInfo>;

}  // namespace confirmations

#endif  // BAT_CONFIRMATIONS_INTERNAL_TOKEN_INFO_H_
