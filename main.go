package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/SeasonPilot/admission-registry/webhook"

	"k8s.io/klog"
)

func main() {
	var param webhook.WebParam

	flag.IntVar(&param.Port, "port", 443, "webhook server port")
	flag.StringVar(&param.CertFile, "certFile", "/etc/", "X509certFile")
	flag.StringVar(&param.KeyFile, "keyFile", "/etc/", "X509keyFile")
	flag.Parse()

	pair, err := tls.LoadX509KeyPair(param.CertFile, param.KeyFile)
	if err != nil {
		return
	}

	server := webhook.WebhookServer{
		Server: &http.Server{
			Addr: fmt.Sprintf(":%d", param.Port),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{pair},
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", server.Validate())
	mux.HandleFunc("/mutate", server.Mutate())

	server.Server.Handler = mux

	go func() {
		err = server.Server.ListenAndServeTLS("", "")
		if err != nil {
			panic(err)
		}
	}()

	klog.Info("Server started")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	klog.Infof("Got OS shutdown signal, gracefully shutting down...")
	err = server.Server.Shutdown(context.Background())
	if err != nil {
		klog.Errorf("HTTP Server Shutdown err: %s", err)
		return
	}
}
