package api

import v1 "k8s.io/api/core/v1"

type HealthWorker struct {
	// Data set on start
	NodeName     string                  `json:"nodeName"`
	ClusterID    string                  `json:"clusterID"`
	Version      string                  `json:"version"`
	Storage      *HealthWorkerStorage    `json:"storage"`
	Sniffer      *HealthWorkerComponent  `json:"sniffer"`
	SnifferStats interface{}             `json:"snifferStats"`
	Tracer       *HealthWorkerComponent  `json:"tracer"`
	TracerStats  interface{}             `json:"tracerStats"`
	BPFFilter    string                  `json:"bpfFilter"`
	LicenseData  HealthWorkerLicenseData `json:"licenseData"`
}

type HealthWorkerComponent struct {
	Timestamp            string                  `json:"timestamp"`
	CPUUsage             float64                 `json:"cpuUsage"`
	MemoryUsage          float64                 `json:"memoryUsage"`
	LastRestartReason    string                  `json:"lastRestartReason"`
	LastRestartTimestamp string                  `json:"lastRestartTimestamp"`
	Resources            v1.ResourceRequirements `json:"resources"`
	Restarts             int                     `json:"restarts"`
}

type HealthWorkerStorage struct {
	Requested uint64 `json:"requested"`
	Usage     uint64 `json:"usage"`
}

type HealthWorkerLicenseData struct {
	ProcessedBytes int64 `json:"processedBytes"`
	ItemsGenerated int64 `json:"itemsGenerated"`
	WsWrites       int64 `json:"wsWrites"`
	StartTime      int64 `json:"startTime"`
}

type HealthHub struct {
	Workers              []HealthHubWorker       `json:"workers"`
	Nodes                []HealthHubNode         `json:"nodes"`
	NodeName             string                  `json:"nodeName"`
	ClusterID            string                  `json:"clusterID"`
	Version              string                  `json:"version"`
	Timestamp            string                  `json:"timestamp"`
	CPUUsage             float64                 `json:"cpuUsage"`
	MemoryUsage          float64                 `json:"memoryUsage"`
	LastRestartReason    string                  `json:"lastRestartReason"`
	LastRestartTimestamp string                  `json:"lastRestartTimestamp"`
	Resources            v1.ResourceRequirements `json:"resources"`
	Restarts             int                     `json:"restarts"`
}

type HealthHubWorker struct {
	Addr    string `json:"addr"`
	PodName string `json:"podName"`
}

type HealthHubNode struct {
	NodeName string `json:"nodeName"`
	PodCount int    `json:"podCount"`
}
