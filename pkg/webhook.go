package pkg

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/klog"
)

const (
	AnnotationMutateKey = "io.season.admission-registry/mutate" // io.season.admission-registry/mutate=no/off/false/n
	AnnotationStatusKey = "io.season.admission-registry/status" // io.season.admission-registry/status=mutated
)

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

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
		data, err := ioutil.ReadAll(request.Body)
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
	if contentType != "application/json" { // fixme:
		klog.Errorf("Content-Type is %s, but expect application/json", contentType)
		http.Error(writer, fmt.Sprintf("unexpect type %s", contentType), http.StatusBadRequest)
		return
	}

	var reqAdmissionReview admissionv1.AdmissionReview
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

	klog.Infof("reqAdmissionReview: %v", reqAdmissionReview)

	respAdmissionReview := admissionv1.AdmissionReview{
		TypeMeta: reqAdmissionReview.TypeMeta, // fixme: 应该是 req 的 TypeMeta
		Request:  reqAdmissionReview.Request,
		Response: admissionResp,
	}

	klog.Info(fmt.Sprintf("sending admissionReview: %v", respAdmissionReview))

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
	var objectMeta metav1.ObjectMeta

	klog.Infof("AdmissionReview for Kind=%s, Namespace=%s Name=%s UID=%s",
		ar.Kind.Kind, ar.Namespace, ar.Name, ar.UID)

	switch ar.Kind.Kind {
	case "Deployment": // fixme: 大小写敏感 Deployment
		var deploy appsv1.Deployment
		err := json.Unmarshal(ar.Object.Raw, &deploy)
		if err != nil {
			klog.Errorf("json unmarshal err: %s", err)
			return &admissionv1.AdmissionResponse{
				UID: ar.UID,
				Result: &metav1.Status{
					Message: err.Error(),
					Code:    http.StatusBadRequest,
				},
			}
		}
		objectMeta = deploy.ObjectMeta
	case "Service":
		var service corev1.Service
		err := json.Unmarshal(ar.Object.Raw, &service)
		if err != nil {
			klog.Errorf("json unmarshal err: %s", err)
			return &admissionv1.AdmissionResponse{
				UID: ar.UID,
				Result: &metav1.Status{
					Message: err.Error(),
					Code:    http.StatusBadRequest,
				},
			}
		}
		objectMeta = service.ObjectMeta
	default:
		klog.Infof("Can't handle the kind(%s) object", ar.Kind.Kind)
		return &admissionv1.AdmissionResponse{
			UID:     ar.UID,
			Allowed: false,
			Result: &metav1.Status{
				Message: fmt.Sprintf("Can't handle the kind(%s) object", ar.Kind.Kind),
				Code:    http.StatusBadRequest,
			},
		}
	}

	// 判断是否需要 mutate
	if !mutationRequired(objectMeta) {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
			UID:     ar.UID,
			Result: &metav1.Status{
				Message: "No mutate required",
				Code:    http.StatusOK,
			},
		}
	}

	var patchs []patchOperation
	annos := map[string]string{
		AnnotationStatusKey: "mutated",
	}
	patchs = append(patchs, mutateAnnotation(objectMeta.GetAnnotations(), annos)...)

	bytePatchs, err := json.Marshal(patchs)
	if err != nil {
		klog.Errorf("Can't marshal patchs err: %s", err.Error())
		return &admissionv1.AdmissionResponse{
			UID: ar.UID,
			Result: &metav1.Status{
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			},
		}
	}

	return &admissionv1.AdmissionResponse{
		UID:     ar.UID, // fixme: UID 一定要返回
		Allowed: true,
		Result: &metav1.Status{
			Message: "object mutated",
			Code:    http.StatusOK,
		},
		Patch: bytePatchs,
		PatchType: func() *admissionv1.PatchType {
			p := admissionv1.PatchTypeJSONPatch
			return &p
		}(),
	}
}

func mutationRequired(metadata metav1.ObjectMeta) (required bool) {
	annotations := metadata.GetAnnotations()
	if annotations == nil {
		return true
	}

	// 判断 AnnotationMutateKey
	switch strings.ToLower(annotations[AnnotationMutateKey]) {
	case "no", "n", "false", "off":
		required = false
	default:
		required = true
	}

	// 判断 AnnotationStatusKey
	if strings.ToLower(annotations[AnnotationStatusKey]) == "mutated" {
		required = false
	}
	klog.Infof("Mutation policy for %s/%s: required: %v", metadata.Name, metadata.Namespace, required)

	return
}

func mutateAnnotation(target, add map[string]string) (patchOperations []patchOperation) {
	if target == nil {
		target = make(map[string]string, len(add))
	}

	for k, v := range add {
		var p patchOperation
		if _, ok := target[k]; ok {
			p = patchOperation{
				Op:    "replace",                    // fixme:
				Path:  "/metadata/annotations/" + k, // fixme:
				Value: v,                            //fixme:
			}
		} else {
			p = patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					k: v,
				},
			}
		}
		patchOperations = append(patchOperations, p)
	}

	return
}
