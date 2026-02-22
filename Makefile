BINARY=analyzer

build:
	go build -o $(BINARY) main.go
	sudo setcap cap_net_raw,cap_net_admin=eip ./$(BINARY)

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)