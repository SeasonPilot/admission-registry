package pkg

import (
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func InitK8sCli() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

func WriteFile(path string, bytes []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close() // fixme:

	_, err = file.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}
