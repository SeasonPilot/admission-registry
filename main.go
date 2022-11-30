package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/SeasonPilot/admission-registry/pkg"

	"k8s.io/klog"
)

func main() {
	var param pkg.WebParam

	flag.IntVar(&param.Port, "port", 443, "webhook server port")
	flag.StringVar(&param.CertFile, "tlsCertFile", "/etc/webhook/certs/tls.crt", "x509 certification file")
	flag.StringVar(&param.KeyFile, "tlsKeyFile", "/etc/webhook/certs/tls.key", "x509 private key file")
	flag.Parse()

	pair, err := tls.LoadX509KeyPair(param.CertFile, param.KeyFile)
	if err != nil {
		return
	}
	server := pkg.WebhookServer{
		Server: &http.Server{
			Addr: fmt.Sprintf(":%d", param.Port),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{pair},
			},
		},
		WhiteListRegistries: strings.Split(os.Getenv("WHITELIST_REGISTRIES"), ","),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", server.Handler)
	mux.HandleFunc("/mutate", server.Handler)

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
