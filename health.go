package api

import v1 "k8s.io/api/core/v1"

type HealthWorker struct {
	// Data set on start
	Hostname  string `json:"hostname"`
	ClusterID string `json:"clusterID"`

	Sniffer *HealthWorkerComponent `json:"sniffer"`
	Tracer  *HealthWorkerComponent `json:"tracer"`
}

type HealthWorkerComponent struct {
	Timestamp         string                  `json:"timestamp"`
	CPUUsage          float64                 `json:"cpuUsage"`
	MemoryAlloc       uint64                  `json:"memoryAlloc"`
	MemoryUsage       float64                 `json:"memoryUsage"`
	LastRestartReason string                  `json:"lastRestartReason"`
	Resources         v1.ResourceRequirements `json:"resources"`
	Restarts          int                     `json:"restarts"`
}
