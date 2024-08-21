package api

import v1 "k8s.io/api/core/v1"

type HealthWorker struct {
	// Data set on start
	NodeName  string `json:"nodeName"`
	ClusterID string `json:"clusterID"`
	Version   string `json:"version"`

	Sniffer *HealthWorkerComponent `json:"sniffer"`
	Tracer  *HealthWorkerComponent `json:"tracer"`
}

type HealthWorkerComponent struct {
	Timestamp            string                  `json:"timestamp"`
	CPUUsage             float64                 `json:"cpuUsage"`
	MemoryAlloc          uint64                  `json:"memoryAlloc"`
	MemoryUsage          float64                 `json:"memoryUsage"`
	LastRestartReason    string                  `json:"lastRestartReason"`
	LastRestartTimestamp string                  `json:"lastRestartTimestamp"`
	Resources            v1.ResourceRequirements `json:"resources"`
	Restarts             int                     `json:"restarts"`
}

type HealthHub struct {
	Workers              []HealthHubWorker       `json:"workers"`
	NodeName             string                  `json:"nodeName"`
	ClusterID            string                  `json:"clusterID"`
	Version              string                  `json:"version"`
	Timestamp            string                  `json:"timestamp"`
	CPUUsage             float64                 `json:"cpuUsage"`
	MemoryAlloc          uint64                  `json:"memoryAlloc"`
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
