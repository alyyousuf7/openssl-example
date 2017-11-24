#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <pthread.h>
#include <stdint.h>

static pthread_mutex_t *openssl_mutex = NULL;

static void openssl_locking_callback(int mode, int n, const char *file, int line) {
	pthread_mutex_t *mutex = &openssl_mutex[n];
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(mutex);
	} else {
		pthread_mutex_unlock(mutex);
	}
}

static void openssl_threadid_callback(CRYPTO_THREADID *openssl_threadid) {
	pthread_t threadid = pthread_self();
	CRYPTO_THREADID_set_pointer(openssl_threadid, (void *)threadid);
}

pthread_key_t thread_cleanup_key;

static void thread_cleanup(void * x) {
	ERR_remove_thread_state(NULL);
}

int FIPS_init(void) {
	int mutex_count = CRYPTO_num_locks();
	openssl_mutex = calloc(mutex_count, sizeof(pthread_mutex_t));
	for (int i = 0; i < mutex_count; i++) {
			pthread_mutex_init(&openssl_mutex[i], NULL);
	}
	CRYPTO_set_locking_callback(openssl_locking_callback);
	CRYPTO_THREADID_set_callback(openssl_threadid_callback);

	SSL_load_error_strings();
	SSL_library_init();

	if (FIPS_mode_set(1) != 1) {
		return 0;
	}

	if (RAND_status() != 1) {
		return 0;
	}

	if (pthread_key_create(&thread_cleanup_key, thread_cleanup) != 0) {
		return 0;
	}

	return 1;
}

void schedule_thread_cleanup(void) {
	pthread_setspecific(thread_cleanup_key, (void *)(1));
}
