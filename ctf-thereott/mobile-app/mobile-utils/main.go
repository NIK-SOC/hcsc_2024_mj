package main

import (
	"C"
)
import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
)

const hmac_key string = "K7Sx5Io4gYXH4yQTTv25P7NQA9nQnuSq7ifXUiRf"

const keyThirdPart string = "n4kiQV75smoR5gW2GeStqbM8apA8xd1h"

func StringToMD5(input string) string {
	hash := md5.New()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}

func ChaChaDecrypt(input string) string {
	key := []byte("Porcica1Porcica10000000000000000")
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}
	nonce := make([]byte, cipher.NonceSize())
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := cipher.Open(nil, nonce, decoded, nil)
	if err != nil {
		log.Fatal(err)
	}
	return string(plaintext)
}

func GenerateHMACSHA1Signature(key, data string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

//export BuildStringSecondPart
func BuildStringSecondPart(keyFirstPart, keySecondPart, firstPart, headers, timestamp, payload *C.char) *C.char {
	keyFirstPartGoString := C.GoString(keyFirstPart)
	keySecondPartGoString := C.GoString(keySecondPart)
	firstPartGoString := C.GoString(firstPart)
	headersGoString := C.GoString(headers)
	timestampGoString := C.GoString(timestamp)
	payloadGoString := C.GoString(payload)
	key := keyFirstPartGoString + keySecondPartGoString + ChaChaDecrypt(keyThirdPart) + "uSq7ifXUiRf"

	toAppend := firstPartGoString + StringToMD5(headersGoString) + "\n" + timestampGoString + "\n" + StringToMD5(payloadGoString)
	return C.CString(GenerateHMACSHA1Signature(key, toAppend))
}

func main() {}
