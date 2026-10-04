# SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
# SPDX-License-Identifier: Apache-2.0

BOLD :=  \033[1m
CYAN :=  \033[36m
GREEN := \033[32m
WHITE := \033[37m
RESET := \033[0m

.PHONY: help
help:
	@printf "${BOLD}${WHITE}SLSA Source Tooling Makefile Help\n=================================${RESET}\n"
	@grep -Eh '^[a-zA-Z_-]+:.*?## .*$$' ${MAKEFILE_LIST} | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "${BOLD}${CYAN}%-25s${RESET}%s\n", $$1, $$2}'

.PHONY: fakes
fakes: ## Rebuild the implementation fakes
	go generate ./...

.PHONY: proto
proto: ## Rebuild the code from the protobuf definitions
	hack/generate-protos.sh
