package main

import (
	"bytes"
	"flag"
	"os"
	"fmt"
)

func get_confluent_server() (string, error) {
	var confluentsrv string
	dcfg, err := os.ReadFile("/etc/confluent/confluent.deploycfg")
	if err == nil {
		dcfglines := bytes.Split(dcfg, []byte("\n"))
		for _, dcfgline := range(dcfglines) {
			dkeyval := bytes.Split(dcfgline, []byte(" "))
			if bytes.Contains(dkeyval[0], []byte("deploy_server")) && (bytes.Contains(dkeyval[1], []byte(".")) || bytes.Contains(dkeyval[1], []byte(":"))) {
				confluentsrv = string(dkeyval[1])
				return confluentsrv, nil
			}
		}
	} else {
		_, err := os.ReadFile("/etc/confluent/confluent.info")
		if err != nil {
			return "Unable to determine Confluent server", err
		}
	}
	return "", err
}
func main() {
	var nodename string
	var cacerts string
	var apikey string
	var usejson bool
	var confluentsrv string
	hmacreg := flag.NewFlagSet("hmacregister", flag.ExitOnError)
	hmacreg.StringVar(&apikey, "k", "/etc/confluent/apikey", "Output file for the api key")
	hmacKey := hmacreg.String("i", "", "Identity yaml file")
	hmacreg.StringVar(&cacerts, "c", "/etc/confluent/ca.pem", "Certeficate authorities to use in PEM")
	hmacreg.StringVar(&nodename, "n", "", "Node name")
	hmacreg.StringVar(&confluentsrv, "s", "", "Confluent server to request from")

	invokeapi := flag.NewFlagSet("invoke", flag.ExitOnError)
	invokeapi.StringVar(&nodename, "n", "", "Node name")

	invokeapi.StringVar(&cacerts, "c", "/etc/confluent/ca.pem", "Certeficate authorities to use in PEM")
	invokeapi.StringVar(&apikey, "k", "/etc/confluent/confluent.apikey", "File containing Confluent API key")
	invokeapi.BoolVar(&usejson, "j", false, "Request JSON formatted reply")
	outputfile := invokeapi.String("o", "", "Filename to store download to")
	invokeapi.StringVar(&confluentsrv, "s", "", "Confluent server to request from")



	if len(os.Args) < 2 {
		panic("Insufficient arguments, no subcommand")
	}
	switch os.Args[1] {
		case "hmacregister":
			var err error
			hmacreg.Parse(os.Args[2:])
			if confluentsrv == "" {
				confluentsrv, err = get_confluent_server()
			}
			password, crypted, hmac, err := genpasshmac(*hmacKey)
			if err != nil { panic(err) }
			//apiclient(cacerts, "/confluent-api/self/registerapikey", apikey, nodename, usejson)
			apiclient, err := NewApiClient(cacerts, "", nodename, confluentsrv)
			if err != nil { panic(err) }
			err = apiclient.RegisterKey(crypted, hmac)
			if err != nil { panic(err) }
			outp, err := os.Create(apikey)
			if err != nil { panic(err) }
			defer outp.Close()
			outp.Write([]byte(password))
		case "invoke":
			var err error
			invokeapi.Parse(os.Args[2:])
			if confluentsrv == "" {
				confluentsrv, err = get_confluent_server()
			}
			apiclient, err := NewApiClient(cacerts, apikey, nodename, confluentsrv)
			if err != nil { panic(err) }
			mime := ""
			if usejson {
				mime = "application/json"
			}
			if *outputfile != "" {
				apiclient.Fetch(invokeapi.Arg(0), *outputfile, mime)
			}
			rsp, err := apiclient.GrabText(invokeapi.Arg(0), mime)
			if err != nil { panic(err) }
			fmt.Println(rsp)
		default:
			panic("Unrecognized subcommand")
	}
}
