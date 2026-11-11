all: vet test

test:
	go test -covermode=count -coverprofile=coverage.out .

test-race:
	go test -race -covermode=atomic -count=1 .

showcoverage: test
	go tool cover -html=coverage.out

vet:
	go vet .

lint:
	golangci-lint run
