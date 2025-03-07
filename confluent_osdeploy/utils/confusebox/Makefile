all: confusebox

confusebox: *.go
	go build -ldflags "-w -s" -gcflags=all="-l" -trimpath

clean:
	rm confusebox
