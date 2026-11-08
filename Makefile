.PHONY: go/install go/tidy go/test go/testsum go/test-fips go/test-boring go/lint go/coverage go/vulncheck
.PHONY: generate/key generate/changelog
.PHONY: dev/up dev/down dev/logs
.PHONY: terraform/apply terraform/destroy

go/install:
	go get -v

go/tidy:
	go mod tidy --compat=1.26

go/test:
	go test -v -coverprofile=.coverage.out --cover ./...

go/testsum:
	gotestsum --format testname --no-color=false -- --cover ./...

# aesgcm must work while the Go Cryptographic Module enforces approved-only operation.
go/test-fips:
	GODEBUG=fips140=only gotestsum --format testname --no-color=false -- -count=1 ./providers/aesgcm/...

# aesgcm falls back to cipher.NewGCM when the AES block is not the standard library's.
go/test-boring:
	GOEXPERIMENT=boringcrypto gotestsum --format testname --no-color=false -- -count=1 ./providers/aesgcm/...

go/lint:
	golangci-lint run --allow-parallel-runners

go/coverage:
	go tool cover -html=.coverage.out

go/vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

generate/key:
	openssl rand -hex 32

dev/up:
	docker compose -f testing/docker-compose.yml up -d

dev/down:
	docker compose -f testing/docker-compose.yml down

dev/logs:
	docker compose -f testing/docker-compose.yml logs --tail=50

terraform/apply:
	cd testing/terraform/vault && \
		terraform init && \
		terraform apply -auto-approve

terraform/destroy:
	cd testing/terraform/vault && \
		terraform destroy -auto-approve

generate/changelog:
	changie merge
