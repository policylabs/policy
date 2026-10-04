#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

set -o xtrace

# shellcheck source=/dev/null
source hack/common.sh

cloned_intoto_repo=0
cloned_signer_repo=0

if [ -d "vendor" ]; then
  echo "Reusing vendor directory"
else 
  mkdir vendor
fi

if [ -d "vendor/attestation" ]; then
  echo "Reusing vendored in-toto/attestation directory"
else
  echo "Cloning in-toto/attestation to vendor/"
  git clone --depth=1 https://github.com/in-toto/attestation vendor/attestation
  cloned_intoto_repo=1
fi

if [ -d "vendor/signer" ]; then
  echo "Reusing vendored carabiner/signer directory"
else
  echo "Cloning carabiner/signer to vendor/"
  git clone --depth=1 https://github.com/policylabs/signer vendor/signer
  cloned_signer_repo=1
fi

buf generate

if [ "$cloned_intoto_repo" -eq 1 ]; then
  rm -rf vendor/attestation/
fi
if [ "$cloned_signer_repo" -eq 1 ]; then
  rm -rf vendor/signer
fi

rmdir vendor || :
