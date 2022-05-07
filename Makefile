
go/install:
	go get -v

go/tidy:
	go mod tidy

go/test:
	go test -v -coverprofile=.coverage.out --cover ./...

go/testsum:
	gotestsum --format testname --no-color=false -- --cover ./...

go/lint:
	golangci-lint run

go/coverage:
	go tool cover -html=.coverage.out

generate/key:
	openssl rand -hex 32

dev/up:
	docker-compose -f testing/docker-compose.yml up -d

dev/down:
	docker-compose -f testing/docker-compose.yml down

dev/logs:
	docker-compose -f testing/docker-compose.yml logs --tail=50

terraform/apply:
	cd testing/terraform/vault && terraform init && terraform apply -auto-approve

terraform/destroy:
	cd testing/terraform/vault && terraform destroy -auto-approve
