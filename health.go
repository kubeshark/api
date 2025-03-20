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
	TracerStats  TracerAllStats          `json:"tracerStats"`
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

type TracerAllStats struct {
	Pktmt struct {
		PacketsTotal          uint64
		PacketsProgramEnabled uint64
		PacketsMatchedCgroup  uint64
		PacketsIpv4           uint64
		PacketsIpv6           uint64
		PacketsParsePassed    uint64
		PacketsParseFailed    uint64
		SaveStats             struct {
			SavePackets         uint64
			SaveFailedLogic     uint64
			SaveFailedNotOpened uint64
			SaveFailedFull      uint64
			SaveFailedOther     uint64
		}
	}
	OpensslStats struct {
		UprobesTotal         uint64
		UprobesEnabled       uint64
		UprobesMatched       uint64
		UprobesErrUpdate     uint64
		UretprobesTotal      uint64
		UretprobesEnabled    uint64
		UretprobesMatched    uint64
		UretprobesErrContext uint64
		SaveStats            struct {
			SavePackets         uint64
			SaveFailedLogic     uint64
			SaveFailedNotOpened uint64
			SaveFailedFull      uint64
			SaveFailedOther     uint64
		}
	}
	GotlsStats struct {
		UprobesTotal      uint64
		UprobesEnabled    uint64
		UprobesMatched    uint64
		UretprobesTotal   uint64
		UretprobesEnabled uint64
		UretprobesMatched uint64
		SaveStats         struct {
			SavePackets         uint64
			SaveFailedLogic     uint64
			SaveFailedNotOpened uint64
			SaveFailedFull      uint64
			SaveFailedOther     uint64
		}
	}
}
