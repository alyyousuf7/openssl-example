package openssl

// #cgo pkg-config: openssl
// #cgo LDFLAGS: -ldl
// #cgo CFLAGS: -std=c99
// #include <openssl/err.h>
// #include <openssl/crypto.h>
// #include <stdlib.h>
// extern int FIPS_init(void);
// extern void schedule_thread_cleanup(void);
import "C"
import (
	"log"
	"runtime"
	"strings"
)

func init() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if C.FIPS_init() != 1 {
		log.Fatal(GetError())
	}
}

func Status() (fipsMode bool, version string) {
	return C.FIPS_mode() == 1, "Docker Cryptographic Library 1.0"
}

type Error []string

func (e Error) Error() string {
	switch len(e) {
	case 0:
		return "OpenSSL error"
	case 1:
		return "OpenSSL error: " + e[0]
	default:
		return "OpenSSL error\n" + strings.Join(e, "\n")
	}
}

func X(f func() (success bool)) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	C.ERR_clear_error()
	C.schedule_thread_cleanup()
	if !f() {
		return GetError()
	}
	return nil
}

func GetError() Error {
	var err Error
	for {
		e := C.ERR_get_error()
		if e == 0 {
			break
		}
		msg := C.ERR_error_string(e, nil)
		err = append(err, C.GoString(msg))
	}
	return err
}
