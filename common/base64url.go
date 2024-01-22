package common

import "encoding/base64"

func Base64UrlEncodeNoPadding(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}

func Base64UrlDecodeNoPadding(in string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(in)
}
