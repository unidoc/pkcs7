all: vet unused gosimple staticcheck test

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

unused:
	unused .

gosimple:
	gosimple .

staticcheck:
	staticcheck .

gettools:
	go get -u honnef.co/go/tools/...
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.1
