package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"net/http"
	"crypto/x509"
	"crypto/tls"
)

func main() {
	certauthority := flag.String("c", "/etc/confluent/ca.pem", "Certificate authorities to use, in PEM format")
	targurl := flag.String("u", "", "Url to connect to")
	keyfile := flag.String("k", "/etc/confluent/confluent.apikey", "Confluent API key file")
	nodename := flag.String("n", "", "Node Name")
	usejson := flag.Bool("j", false, "Use JSON")
	flag.Parse()
	certpool := x509.NewCertPool()
	currcacerts, err := os.ReadFile(*certauthority)
	if err != nil {
		panic(err)
	}
	confluentapikey, err := os.ReadFile(*keyfile)
	if confluentapikey[len(confluentapikey) - 1] == 0xa {
		confluentapikey = confluentapikey[:len(confluentapikey)-1]
	}
	if err != nil {
		panic(err)
	}
	certpool.AppendCertsFromPEM(currcacerts)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		},
	}
	rq, err := http.NewRequest(http.MethodGet, *targurl, nil)
	if err != nil { panic(err )}
	if *usejson { rq.Header.Set("Accept", "application/json") }
	if *nodename == "" {
		*nodename, err = os.Hostname()
	}
	rq.Header.Set("CONFLUENT_NODENAME", *nodename)
	fmt.Println(string(confluentapikey))
	rq.Header.Set("CONFLUENT_APIKEY", string(confluentapikey))
	if err != nil { panic(err )}
	rsp, err := client.Do(rq)
	if err != nil { panic(err )}
	rspdata, err := io.ReadAll(rsp.Body)
	rsptxt := string(rspdata)
	fmt.Println(rsptxt)
}

