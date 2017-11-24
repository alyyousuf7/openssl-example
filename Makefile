CFLAGS = -I /usr/local/ssl/include
LDFLAGS = -L /usr/local/ssl/lib -lcrypto -ldl

all: clean bin/gen-ecdsa-key

clean:
	@echo "+ $@"
	@rm -rf bin || true
	@mkdir bin || true

bin/gen-ecdsa-key:
	@echo "+ $@"
	@$(CC) gen-ecdsa-key/main.c -o $@ $(CFLAGS) $(LDFLAGS)

shell: image
	@echo "+ $@"
	docker run -it --rm -v ${PWD}:/root/src openssl:fips

image: clean
	@echo "+ $@"
	@docker build --rm -t openssl:fips .

.PHONY: all clean shell image