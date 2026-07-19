//go:build !pkcs11

package vault

import "errors"

// NewPKCS11KEK is a stub in the default build. PKCS#11 needs cgo and a dynamic
// loader for the vendor module, which the static/distroless image deliberately
// omits. Rebuild with `-tags pkcs11` (and a glibc base image) to enable it.
func NewPKCS11KEK(module, pin, keyLabel, tokenLabel string) (KEK, error) {
	return nil, errors.New("vault: PKCS#11 KEK not built in — rebuild with -tags pkcs11")
}
