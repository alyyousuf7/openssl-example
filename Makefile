CFLAGS = -g -I /usr/local/ssl/include
LDFLAGS = -L /usr/local/ssl/lib -lcrypto -ldl

all: clean
clean:
	@echo "+ $@"
	@rm -rf bin || true
	@rm -rf *.der || true
	@mkdir bin || true

all: bin/aes-encdec
bin/aes-encdec:
	@echo "+ $@"
	@$(CC) aes-encdec/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/gen-ecdsa-key
bin/gen-ecdsa-key:
	@echo "+ $@"
	@$(CC) gen-ecdsa-key/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/gen-ecdsa-sig
bin/gen-ecdsa-sig:
	@echo "+ $@"
	@$(CC) gen-ecdsa-sig/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/gen-rsa-key
bin/gen-rsa-key:
	@echo "+ $@"
	@$(CC) gen-rsa-key/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/gen-rsa-sig
bin/gen-rsa-sig:
	@echo "+ $@"
	@$(CC) gen-rsa-sig/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/hmac
bin/hmac:
	@echo "+ $@"
	@$(CC) hmac/main.c -o $@ -std=c99 $(CFLAGS) $(LDFLAGS)

all: bin/initialize-fips
bin/initialize-fips:
	@echo "+ $@"
	@$(CC) initialize-fips/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/fips-selftest
bin/fips-selftest:
	@echo "+ $@"
	@$(CC) fips-selftest/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/fips-mode-status
bin/fips-mode-status:
	@echo "+ $@"
	@$(CC) fips-mode-status/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/fips-zerorize
bin/fips-zerorize:
	@echo "+ $@"
	@$(CC) fips-zerorize/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/sym-key-gen
bin/sym-key-gen:
	@echo "+ $@"
	@$(CC) sym-key-gen/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/ver-ecdsa-sig
bin/ver-ecdsa-sig:
	@echo "+ $@"
	@$(CC) ver-ecdsa-sig/main.c -o $@ $(CFLAGS) $(LDFLAGS)

all: bin/ver-rsa-sig
bin/ver-rsa-sig:
	@echo "+ $@"
	@$(CC) ver-rsa-sig/main.c -o $@ $(CFLAGS) $(LDFLAGS)

shell: image
	@echo "+ $@"
	docker run -it --rm --privileged -v ${PWD}:/root/src openssl:fips

image: clean
	@echo "+ $@"
	@docker build --rm -t openssl:fips .

.PHONY: all clean shell image