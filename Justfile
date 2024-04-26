lint:
    @echo "Running linter..."
    @golangci-lint run

test:
    @echo "Running tests..."
    @go test -cover ./...

build:
    @echo "Building..."
    @go build ./...

submodule:
  @git submodule update --remote --merge