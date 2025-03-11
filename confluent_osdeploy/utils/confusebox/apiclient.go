package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"net/http"
	"crypto/x509"
	"crypto/tls"
	"strings"
	"errors"
)
type ApiClient struct {
	server string
	urlserver string
	apikey string
	nodename string
	webclient *http.Client
}

func NewApiClient(cafile string, keyfile string, nodename string, server string) (*ApiClient, error) {
	currcacerts, err := os.ReadFile(cafile)
	if err != nil {
		return nil, err
	}
	cacerts  := x509.NewCertPool()
	cacerts.AppendCertsFromPEM(currcacerts)
	apikey := []byte("")
	if keyfile != "" {
		apikey, err = os.ReadFile(keyfile)
		if err != nil {
			return nil, err
		}
		if apikey[len(apikey) - 1] == 0xa {
			apikey = apikey[:len(apikey)-1]
		}
	}
	if nodename == "" {
		cinfo, err := os.ReadFile("/etc/confluent/confliuent.info")
		if err != nil {
			nodename, err = os.Hostname()
			if err != nil { return nil, err }
		}
		cinfolines := bytes.Split(cinfo, []byte("\n"))
		if bytes.Contains(cinfolines[0], []byte("NODENAME")) {
			cnodebytes := bytes.Split(cinfolines[0], []byte(" "))
			nodename = string(cnodebytes[0])
		}
	}
	urlserver := server
	if strings.Contains(server, ":") {
		if strings.Contains(server, "%") && !strings.Contains(server, "%25") {
			server = strings.Replace(server, "%", "%25", 1)
		}
		urlserver = fmt.Sprintf("[%s]", server)
		if strings.Contains(server, "%") {
			server = server[:strings.Index(server, "%")]
		}
	}
	webclient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: cacerts,
				ServerName: server,
			},
		},
	}
	vc := ApiClient{server, urlserver, string(apikey), nodename, webclient}
	return &vc, nil
}

func (apiclient *ApiClient) RegisterKey(crypted string, hmac string) (error) {
	cryptbytes := []byte(crypted)
	cryptbuffer := bytes.NewBuffer(cryptbytes)
	_, err := apiclient.request("/confluent-api/self/registerapikey", "", cryptbuffer, "", hmac)
	return err
}

func (apiclient *ApiClient) Fetch(url string, outputfile string, mime string, body io.Reader) (error)  {
	outp, err := os.Create(outputfile)
	if err != nil { return err }
	defer outp.Close()
	rsp, err := apiclient.request(url, mime, body, "", "")
	if err != nil { return err }
	_, err = io.Copy(outp, rsp)
	return err
}

func (apiclient *ApiClient) GrabText(url string, mime string, body io.Reader) (string, error){
	rsp, err := apiclient.request(url, mime, body, "", "")
	if err != nil { return "", err }
	rspdata, err := io.ReadAll(rsp)
	if err != nil { return "", err }
	rsptxt := string(rspdata)
	return rsptxt, nil
}

func (apiclient *ApiClient) request(url string, mime string, body io.Reader, method string, hmac string) (io.ReadCloser, error) {
	if ! strings.Contains(url, "https://") {
		url = fmt.Sprintf("https://%s%s", apiclient.urlserver, url)
	}
	if method == "" {
		if body != nil {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}
	var err error
	var rq *http.Request
	if body == nil {
		rq, err = http.NewRequest(method, url, nil)
	} else {
		rq, err = http.NewRequest(method, url, body)
	}
	if err != nil { return nil, err }
	if (mime != "") { rq.Header.Set("Accept", mime) }
	rq.Header.Set("CONFLUENT_NODENAME", apiclient.nodename)
	if len(hmac) > 0 {
		rq.Header.Set("CONFLUENT_CRYPTHMAC", hmac)
	} else {

		rq.Header.Set("CONFLUENT_APIKEY", apiclient.apikey)
	}
	rsp, err := apiclient.webclient.Do(rq)
	if err != nil { return nil, err }
	if rsp.StatusCode >= 300 {
		err = errors.New(rsp.Status)
		return nil, err
	}
	return rsp.Body, err
}

