package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

func main() {
	secret := "helloworld"

	fmt.Println("OPT")
	code, err1 := GenerateCode(secret, 1)
	fmt.Println(code)
	if err1 != nil {
		fmt.Println(err1)
	}

	validation, err2 := Validate(code, secret, 1)
	fmt.Println(validation)
	if err2 != nil {
		fmt.Println(err2)
	}
}

const digits int = 8
const algo string = "SHA512"

// GenerateCode generates passcode from secret and counter
func GenerateCode(secret string, counter uint64) (passcode string, err error) {

	secret = strings.ToUpper(secret)
	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret = secret + strings.Repeat("=", 8-n)
	}

	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", errors.New("decoding secret as base32 failed")
	}

	key := make([]byte, 8)
	mac := hmac.New(sha256.New, secretBytes)
	binary.BigEndian.PutUint64(key, counter)

	mac.Write(key)
	macsum := mac.Sum(nil)
	//https://en.it1352.com/article/74b71b42f5f0426d99481bbe9a6190d2.html
	offset := macsum[len(macsum)-1] & 0xf
	value := int64(((int(macsum[offset]) & 0x7f) << 24) | ((int(macsum[offset+1] & 0xff)) << 16) | ((int(macsum[offset+2] & 0xff)) << 8) | (int(macsum[offset+3]) & 0xff))
	mod := int32(value % int64(math.Pow10(digits)))

	return format(mod), nil
}

func format(mod int32) string {
	f := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(f, mod)
}

// Validate validates an HOTP
func Validate(passcode string, secret string, counter uint64) (bool, error) {
	passcode = strings.TrimSpace(passcode)

	if len(passcode) != digits {
		return false, errors.New("decoding secret as base32 failed")
	}

	otpstr, err := GenerateCode(secret, counter)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(otpstr), []byte(passcode)) == 1 {
		return true, nil
	}

	return false, nil
}
