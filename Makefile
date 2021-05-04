default: test

test:
	go test ./...

staticcheck:
	staticcheck ./...
