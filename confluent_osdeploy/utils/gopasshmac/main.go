package main

import (
	"flag"
	//"fmt"
	"github.com/go-crypt/crypt/algorithm/shacrypt"
	"os"
	"crypto/rand"
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
)

func main() {
	hmackeyfile := flag.String("k", "", "Key file for HMAC calculation")
	passfile := flag.String("p", "", "File to write generated password to")
	cryptfile := flag.String("c", "", "File to write crypted form of key to")
	hmacfile := flag.String("m", "", "File to write HMAC value to")
	flag.Parse()
	randbytes := make([]byte, 36)
	_, err := rand.Read(randbytes)
	if err != nil {
		panic(err)
	}
	newpasswd := base64.StdEncoding.EncodeToString(randbytes)
	hasher, err := shacrypt.New(shacrypt.WithVariant(shacrypt.VariantSHA256), shacrypt.WithIterations(5000))
	if err != nil {
		panic(err)
	}

	digest, err := hasher.Hash(newpasswd)
	if err != nil {
		panic(err)
	}
	cryptdata := []byte(digest.Encode())
	err = os.WriteFile(*passfile, []byte(newpasswd), 0600)
	if err != nil { panic(err )}
	err = os.WriteFile(*cryptfile, cryptdata, 0600)
	if err != nil { panic(err )}
	keydata, err := os.ReadFile(*hmackeyfile)
	if err != nil { panic(err )}
	hmacer := hmac.New(sha256.New, keydata)
	hmacer.Write(cryptdata)
	hmacresult := hmacer.Sum(nil)
	hmacout := []byte(base64.StdEncoding.EncodeToString(hmacresult))
	err = os.WriteFile(*hmacfile, hmacout, 0600)
	if err != nil { panic(err )}
}

