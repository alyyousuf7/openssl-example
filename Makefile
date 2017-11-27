CFLAGS = -I /usr/local/ssl/include
LDFLAGS = -L /usr/local/ssl/lib -lcrypto -ldl

all: clean bin/initialize-fips bin/fips-selftest bin/fips-mode-status bin/fips-zerorize bin/gen-ecdsa-key

clean:
	@echo "+ $@"
	@rm -rf bin || true
	@mkdir bin || true

bin/initialize-fips:
	@echo "+ $@"
	@$(CC) initialize-fips/main.c -o $@ $(CFLAGS) $(LDFLAGS)

bin/fips-selftest:
	@echo "+ $@"
	@$(CC) fips-selftest/main.c -o $@ $(CFLAGS) $(LDFLAGS)

bin/fips-mode-status:
	@echo "+ $@"
	@$(CC) fips-mode-status/main.c -o $@ $(CFLAGS) $(LDFLAGS)

bin/fips-zerorize:
	@echo "+ $@"
	@$(CC) fips-zerorize/main.c -o $@ $(CFLAGS) $(LDFLAGS)

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