package pkg

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/klog"
)

type WebParam struct {
	Port     int
	CertFile string
	KeyFile  string
}

type WebhookServer struct {
	Server              *http.Server
	WhiteListRegistries []string
}

func (s WebhookServer) Handler(writer http.ResponseWriter, request *http.Request) {
	var (
		scheme       = runtime.NewScheme()
		factory      = serializer.NewCodecFactory(scheme)
		deserializer = factory.UniversalDeserializer()
	)

	var body []byte

	if request.Body != nil {
		data, err := io.ReadAll(request.Body)
		if err == nil {
			body = data
		}
	}

	if len(body) == 0 && body != nil {
		klog.Error("empty data body")
		http.Error(writer, "empty data body", http.StatusBadRequest)
		return
	}

	// 校验 content-type
	contentType := request.Header.Get("Content-Type")
	if contentType != "application-json" {
		klog.Errorf("Content-Type is %s, but expect application/json", contentType)
		http.Error(writer, fmt.Sprintf("unexpect type %s", contentType), http.StatusBadRequest)
		return
	}

	var reqAdmissionReview admissionv1.AdmissionReview
	var respAdmissionReview admissionv1.AdmissionReview
	var admissionResp *admissionv1.AdmissionResponse
	_, _, err := deserializer.Decode(body, nil, &reqAdmissionReview)
	if err != nil {
		klog.Errorf("Can't decode body: %v", err)
		admissionResp = &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
				Code:    http.StatusInternalServerError,
			},
		}
		return
	} else {
		//判断 path
		if request.URL.Path == "/mutate" {
			admissionResp = s.mutate(reqAdmissionReview.Request)
		} else if request.URL.Path == "/validate" {
			admissionResp = s.validate(reqAdmissionReview.Request)
		}
	}

	respAdmissionReview = admissionv1.AdmissionReview{
		TypeMeta: respAdmissionReview.TypeMeta,
		Request:  reqAdmissionReview.Request,
		Response: admissionResp,
	}

	klog.Info(fmt.Sprintf("sending response: %v", respAdmissionReview.Response))

	data, err := json.Marshal(respAdmissionReview)
	if err != nil {
		klog.Errorf("json marshal err: %s", err)
		http.Error(writer, fmt.Sprintf("Can't encode response: %v", err), http.StatusBadRequest)
		return
	}

	klog.Info("Ready to write response...")

	_, err = writer.Write(data)
	if err != nil {
		klog.Errorf("Write resp err: %v", err)
		http.Error(writer, fmt.Sprintf("Can't write reponse: %v", err), http.StatusBadRequest)
	}
}

func (s WebhookServer) validate(ar *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	var (
		pod     corev1.Pod
		message string
		allowed = true
		code    = http.StatusOK
	)

	klog.Infof("AdmissionRequest for Kind=%s, Namespace=%s Name=%s UID=%s",
		ar.Kind, ar.Namespace, ar.Name, ar.UID)

	err := json.Unmarshal(ar.Object.Raw, &pod)
	if err != nil {
		klog.Errorf("Can't unmarshal object raw: %v", err)
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			},
		}
	}

	// 处理真正的业务逻辑
	for _, c := range pod.Spec.Containers {
		var whitelisted = false
		for _, w := range s.WhiteListRegistries {
			if strings.HasPrefix(c.Image, w) {
				whitelisted = true
				break
			}
		}
		if !whitelisted {
			allowed = false
			code = http.StatusForbidden
			message = fmt.Sprintf("%s image comes from an untrusted registry! Only images from %v are allowed.", c.Image, s.WhiteListRegistries)
			break
		}
	}

	return &admissionv1.AdmissionResponse{
		UID:     ar.UID,
		Allowed: allowed,
		Result: &metav1.Status{
			Message: message,
			Code:    int32(code),
		},
	}
}

func (s WebhookServer) mutate(ar *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	return nil
}
