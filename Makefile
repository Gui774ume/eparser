all: build install

build:
	mkdir -p bin/
	go build -o bin/ ./...

install:
	sudo cp ./bin/eparser /usr/bin/
