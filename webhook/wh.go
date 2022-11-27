package webhook

import "net/http"

type WebParam struct {
	Port     int
	CertFile string
	KeyFile  string
}

type WebhookServer struct {
	Server              *http.Server
	WhiteListRegistries []string
}

func (s WebhookServer) Validate() func(writer http.ResponseWriter, request *http.Request) {
	return nil
}

func (s WebhookServer) Mutate() func(http.ResponseWriter, *http.Request) {
	return nil
}
