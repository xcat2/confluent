package main

import (
	"bytes"
	"github.com/go-crypt/crypt/algorithm/shacrypt"
	"os"
	"crypto/rand"
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
)

func genpasshmac(hmackeyfile string) (string, string, string, error)  {
	randbytes := make([]byte, 36)
	_, err := rand.Read(randbytes)
	if err != nil {
		panic(err)
	}
	password := base64.StdEncoding.EncodeToString(randbytes)
	hasher, err := shacrypt.New(shacrypt.WithVariant(shacrypt.VariantSHA256), shacrypt.WithIterations(5000))
	if err != nil {
		panic(err)
	}

	digest, err := hasher.Hash(password)
	if err != nil {
		panic(err)
	}
	cryptpass := digest.Encode()
	hmackey, err := os.ReadFile(hmackeyfile)
	if err != nil { return "", "", "", err }
	keylines := bytes.Split(hmackey, []byte("\n"))
	if bytes.Contains(keylines[0], []byte("apitoken:")) {
		keyparts := bytes.Split(keylines[0], []byte(" "))
		hmackey = keyparts[1]
	}

	hmacer := hmac.New(sha256.New, hmackey)
	hmacer.Write([]byte(cryptpass))
	hmacresult := hmacer.Sum(nil)
	hmacout := base64.StdEncoding.EncodeToString(hmacresult)
	return password, cryptpass, hmacout, nil
}

