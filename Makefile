SOURCES := $(shell find . -name '*.go')
BINARY := scanner-anchore
IMAGE_TAG := poc
IMAGE := cafeliker/harbor-scanner-anchore:$(IMAGE_TAG)

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/scanner-anchore/main.go

container: build
	docker build -t $(IMAGE) .

container-run: container
	docker run --name scanner-anchore --rm -d -p 8080:8080 $(IMAGE)
