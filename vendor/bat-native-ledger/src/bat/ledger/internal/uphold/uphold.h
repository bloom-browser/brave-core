/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVELEDGER_UPHOLD_UPHOLD_H_
#define BRAVELEDGER_UPHOLD_UPHOLD_H_

#include <stdint.h>

#include <string>
#include <map>
#include <memory>

#include "bat/ledger/ledger.h"
#include "bat/ledger/internal/uphold/uphold_user.h"

namespace bat_ledger {
class LedgerImpl;
}

namespace braveledger_uphold {

struct Transaction {
  std::string address;
  double amount;
  std::string message;
};

class UpholdTransfer;
class UpholdCard;
class UpholdAuthorization;
class UpholdWallet;

using FetchBalanceCallback = std::function<void(ledger::Result, double)>;
using CreateCardCallback =
    std::function<void(ledger::Result, const std::string&)>;
using CreateAnonAddressCallback =
    std::function<void(ledger::Result, const std::string&)>;

class Uphold {
 public:
  explicit Uphold(bat_ledger::LedgerImpl* ledger);

  ~Uphold();

  void Initialize();

  void StartContribution(
      const std::string& contribution_id,
      ledger::ServerPublisherInfoPtr info,
      const double amount,
      ledger::ResultCallback callback);

  void FetchBalance(FetchBalanceCallback callback);

  void TransferFunds(
      const double amount,
      const std::string& address,
      ledger::TransactionCallback callback);

  void WalletAuthorization(
      const std::map<std::string, std::string>& args,
      ledger::ExternalWalletAuthorizationCallback callback);

  void TransferAnonToExternalWallet(ledger::ExternalWalletCallback callback);

  void GenerateExternalWallet(ledger::ExternalWalletCallback callback);

  void CreateCard(CreateCardCallback callback);

  void DisconnectWallet();

  void GetUser(GetUserCallback callback);

  void CreateAnonAddressIfNecessary(CreateAnonAddressCallback callback);

  void OnTimer(const uint32_t timer_id);

 private:
  void ContributionCompleted(
      const ledger::Result result,
      const std::string& transaction_id,
      const std::string& contribution_id,
      const double fee,
      const std::string& publisher_key,
      ledger::ResultCallback callback);

  void OnFetchBalance(
      const ledger::UrlResponse& response,
      FetchBalanceCallback callback);

  void OnTransferAnonToExternalWalletCallback(
      const ledger::Result result,
      ledger::ExternalWalletCallback callback);

  void SaveTransferFee(ledger::TransferFeePtr transfer_fee);

  void OnTransferFeeCompleted(
      const ledger::Result result,
      const std::string& transaction_id,
      const ledger::TransferFee& transfer_fee);

  void TransferFee(const ledger::TransferFee& transfer_fee);

  void SetTimer(uint32_t* timer_id, uint64_t start_timer_in = 0);

  std::unique_ptr<UpholdTransfer> transfer_;
  std::unique_ptr<UpholdCard> card_;
  std::unique_ptr<UpholdUser> user_;
  std::unique_ptr<UpholdAuthorization> authorization_;
  std::unique_ptr<UpholdWallet> wallet_;
  bat_ledger::LedgerImpl* ledger_;  // NOT OWNED
};

}  // namespace braveledger_uphold
#endif  // BRAVELEDGER_UPHOLD_UPHOLD_H_
