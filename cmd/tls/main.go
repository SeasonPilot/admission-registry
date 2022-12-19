package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/SeasonPilot/admission-registry/pkg"

	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	// CA 配置
	var subject = pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{"Beijing"},
		OrganizationalUnit: []string{"Beijing"},
		Locality:           []string{"season.io"},
		Province:           []string{"season.io"},
	}
	var ca = &x509.Certificate{
		SerialNumber:          big.NewInt(2021),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Panic(err)
	}

	//1. 创建根 CA 证书
	//生成 ca ca-key
	certificate, err := x509.CreateCertificate(rand.Reader, ca, ca, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Panic(err)
	}

	// PEM编码
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	})
	if err != nil {
		log.Panic(err)
	}

	//2. 创建服务器证书
	//创建 Server 端证书
	//cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json \
	//-hostname=admission-registry.default.svc -profile=server server-csr.json | cfssljson -bare server
	dnsNames := []string{
		"admission-registry",
		"admission-registry.default",
		"admission-registry.default.svc",
		"admission-registry.default.svc.cluster.local",
	}
	commonName := "admission-registry.default.svc"
	subject.CommonName = commonName //

	srvCert := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		SubjectKeyId: []byte{1, 2, 3, 4, 6}, //
		DNSNames:     dnsNames,              //
	}

	srvPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Panic(err)
	}

	srvCertificate, err := x509.CreateCertificate(rand.Reader, srvCert, ca, &srvPrivKey.PublicKey, privateKey) //fixme: 1. 应该用ca的私钥给加密;2. pub的值要用指针
	if err != nil {
		log.Panic(err)
	}

	srvCertPEM := new(bytes.Buffer)
	err = pem.Encode(srvCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: srvCertificate,
	})
	if err != nil {
		log.Panic(err)
	}

	srvPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(srvPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(srvPrivKey),
	})
	if err != nil {
		log.Panic(err)
	}

	//
	err = os.Mkdir("/etc/webhook/certs/", 0666)
	if err != nil {
		log.Panic(err)
	}

	err = pkg.WriteFile("/etc/webhook/certs/cert.pem", srvCertPEM.Bytes())
	if err != nil {
		log.Panic(err)
	}

	err = pkg.WriteFile("/etc/webhook/certs/cert-key.pem", srvPrivKeyPEM.Bytes())
	if err != nil {
		log.Panic(err)
	}

	log.Println("webhook server tls generated successfully")

	err = CreateAdmissionConfig(caPEM.Bytes()) // fixme: 入参使用的是 ca.pem 文件内容的 base64 值
	if err != nil {
		log.Panic(err)
	}

	log.Println("webhook admission configuration object generated successfully")
}

func CreateAdmissionConfig(ca []byte) error {
	cli, err := pkg.InitK8sCli()
	if err != nil {
		return err
	}

	webhookNamespace := os.Getenv("WEBHOOK_NAMESPACE")
	validatingName := os.Getenv("VALIDATE_CONFIG")
	mutatingName := os.Getenv("MUTATE_CONFIG")
	srvName := os.Getenv("WEBHOOK_SERVICE")
	validatingPath := os.Getenv("VALIDATE_PATH")
	mutatingPath := os.Getenv("MUTATE_PATH")

	ctx := context.Background()
	if validatingName != "" {
		validateAdmissionClient := cli.AdmissionregistrationV1().ValidatingWebhookConfigurations()
		validatingCfg := &v1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: validatingName,
			},
			Webhooks: []v1.ValidatingWebhook{
				{
					Name: "io.season.admission-registry",
					ClientConfig: v1.WebhookClientConfig{
						Service: &v1.ServiceReference{
							Namespace: webhookNamespace,
							Name:      srvName,
							Path:      &validatingPath,
						},
						CABundle: ca,
					},
					Rules: []v1.RuleWithOperations{{
						Operations: []v1.OperationType{"CREATE"},
						Rule: v1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					}},
					SideEffects:             nil,
					AdmissionReviewVersions: []string{"v1"},
				},
			},
		}
		// 判断是否已经存在 ValidatingWebhookConfigurations
		_, err = validateAdmissionClient.Get(ctx, validatingName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) { // 判断是否已经存在 ValidatingWebhookConfigurations
				_, err = validateAdmissionClient.Create(ctx, validatingCfg, metav1.CreateOptions{})
				if err != nil {
					return err
				}
			} else {
				return err
			}
		} else { // 如果存在则更新 ValidatingWebhookConfigurations
			_, err = validateAdmissionClient.Update(ctx, validatingCfg, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
	}

	if mutatingName != "" {
		mutatingCli := cli.AdmissionregistrationV1().MutatingWebhookConfigurations()

		mutatingCfg := &v1.MutatingWebhookConfiguration{
			Webhooks: []v1.MutatingWebhook{
				{
					Name: mutatingName,
					ClientConfig: v1.WebhookClientConfig{
						Service: &v1.ServiceReference{
							Namespace: webhookNamespace,
							Name:      srvName,
							Path:      &mutatingPath,
						},
						CABundle: ca,
					},
					Rules: []v1.RuleWithOperations{
						{
							Operations: []v1.OperationType{"CREATE"},
							Rule: v1.Rule{
								APIGroups:   []string{"app", ""},
								APIVersions: []string{"v1"},
								Resources:   []string{"deployments", "services"},
							},
						},
					},
					SideEffects:             nil,
					AdmissionReviewVersions: []string{"v1"},
				},
			},
		}

		_, err = mutatingCli.Get(ctx, mutatingName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				_, err = mutatingCli.Create(ctx, mutatingCfg, metav1.CreateOptions{})
				if err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			_, err = mutatingCli.Update(ctx, mutatingCfg, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}

	}
	return nil
}
