export GOPATH := $(shell pwd)
default: build

init:
	rm -f bin/server bin/main bin/auth-server
	@cd src/main && go get

build: init
	go build -o bin/auth-server src/main/main.go 

run: build
	@pkill ^auth-server$ || :
	bin/auth-server>log.txt 2>&1 &

log: run
	tail -f -n2 log.txt
