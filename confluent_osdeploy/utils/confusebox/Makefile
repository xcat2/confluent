all: confusebox

confusebox: *.go
	go build -ldflags "-w -s" -gcflags=all="-l" -trimpath
	upx --brute confusebox

clean:
	rm confusebox
