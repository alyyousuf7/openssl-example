#include <openssl/ssl.h>

int FIPS_init(int mode) {
	return FIPS_mode_set(mode);
}
