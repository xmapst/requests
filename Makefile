all: test vet

test:
	go test -v ./...

vet:
	go vet ./...
