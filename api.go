package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kubeshark/gopacket"
	corev1 "k8s.io/api/core/v1"
)

type Protocol struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Abbreviation    string   `json:"abbr"`
	LongName        string   `json:"longName"`
	Macro           string   `json:"macro"`
	BackgroundColor string   `json:"backgroundColor"`
	ForegroundColor string   `json:"foregroundColor"`
	FontSize        int8     `json:"fontSize"`
	ReferenceLink   string   `json:"referenceLink"`
	Ports           []string `json:"ports"`
	Layer4          string   `json:"layer4"`
	Layer3          string   `json:"layer3"`
	Priority        uint8    `json:"priority"`
}

type ResolutionMechanism string

const (
	ResolutionMechanismNone         ResolutionMechanism = "none"
	ResolutionMechanismIp           ResolutionMechanism = "ip"
	ResolutionMechanismIpAndPort    ResolutionMechanism = "ip-and-port"
	ResolutionMechanismDns          ResolutionMechanism = "dns"
	ResolutionMechanismHttpHeader   ResolutionMechanism = "http-header"
	ResolutionMechanismCgroupID     ResolutionMechanism = "cgroup-id"
	ResolutionMechanismContainerID  ResolutionMechanism = "container-id"
	ResolutionMechanismSyscall      ResolutionMechanism = "syscall"
	ResolutionMechanismSidecarProxy ResolutionMechanism = "sidecar-proxy"
)

type Resolution struct {
	IP                  string              `json:"ip"`
	Port                string              `json:"port"`
	Name                string              `json:"name"`
	Namespace           string              `json:"namespace"`
	Pod                 *corev1.Pod         `json:"pod"`
	EndpointSlice       *corev1.Endpoints   `json:"endpointSlice"`
	Service             *corev1.Service     `json:"service"`
	CgroupID            uint                `json:"cgroupId"`
	ContainerID         string              `json:"containerId"`
	SocketID            uint                `json:"socketId"`
	ProcessID           int                 `json:"processId"`
	ParentProcessID     int                 `json:"parentProcessId"`
	HostProcessID       int                 `json:"hostProcessId"`
	HostParentProcessID int                 `json:"hostParentProcessId"`
	ProcessName         string              `json:"processName"`
	ProcessPath         string              `json:"processPath"`
	ResolutionMechanism ResolutionMechanism `json:"resolutionMechanism"`
	sync.Mutex
}

func (resolution *Resolution) GetIP() string {
	resolution.Lock()
	iP := resolution.IP
	resolution.Unlock()
	return iP
}

func (resolution *Resolution) GetPort() string {
	resolution.Lock()
	port := resolution.Port
	resolution.Unlock()
	return port
}

func (resolution *Resolution) GetName() string {
	resolution.Lock()
	name := resolution.Name
	resolution.Unlock()
	return name
}

func (resolution *Resolution) GetNamespace() string {
	resolution.Lock()
	namespace := resolution.Namespace
	resolution.Unlock()
	return namespace
}

func (resolution *Resolution) GetPod() *corev1.Pod {
	resolution.Lock()
	pod := resolution.Pod
	resolution.Unlock()
	return pod
}

func (resolution *Resolution) GetEndpointSlice() *corev1.Endpoints {
	resolution.Lock()
	endpointSlice := resolution.EndpointSlice
	resolution.Unlock()
	return endpointSlice
}

func (resolution *Resolution) GetService() *corev1.Service {
	resolution.Lock()
	service := resolution.Service
	resolution.Unlock()
	return service
}

func (resolution *Resolution) GetCgroupID() uint {
	resolution.Lock()
	cgroupID := resolution.CgroupID
	resolution.Unlock()
	return cgroupID
}

func (resolution *Resolution) GetContainerID() string {
	resolution.Lock()
	containerID := resolution.ContainerID
	resolution.Unlock()
	return containerID
}

func (resolution *Resolution) GetSocketID() uint {
	resolution.Lock()
	socketID := resolution.SocketID
	resolution.Unlock()
	return socketID
}

func (resolution *Resolution) GetProcessID() int {
	resolution.Lock()
	processID := resolution.ProcessID
	resolution.Unlock()
	return processID
}

func (resolution *Resolution) GetParentProcessID() int {
	resolution.Lock()
	parentProcessID := resolution.ParentProcessID
	resolution.Unlock()
	return parentProcessID
}

func (resolution *Resolution) GetHostProcessID() int {
	resolution.Lock()
	hostProcessID := resolution.HostProcessID
	resolution.Unlock()
	return hostProcessID
}

func (resolution *Resolution) GetHostParentProcessID() int {
	resolution.Lock()
	hostParentProcessID := resolution.HostParentProcessID
	resolution.Unlock()
	return hostParentProcessID
}

func (resolution *Resolution) GetProcessName() string {
	resolution.Lock()
	processName := resolution.ProcessName
	resolution.Unlock()
	return processName
}

func (resolution *Resolution) GetProcessPath() string {
	resolution.Lock()
	processPath := resolution.ProcessPath
	resolution.Unlock()
	return processPath
}

func (resolution *Resolution) GetResolutionMechanism() ResolutionMechanism {
	resolution.Lock()
	resolutionMechanism := resolution.ResolutionMechanism
	resolution.Unlock()
	return resolutionMechanism
}

func (resolution *Resolution) SetIP(IP string) *Resolution {
	resolution.Lock()
	resolution.IP = IP
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetPort(Port string) *Resolution {
	resolution.Lock()
	resolution.Port = Port
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetName(Name string) *Resolution {
	resolution.Lock()
	resolution.Name = Name
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetNamespace(Namespace string) *Resolution {
	resolution.Lock()
	resolution.Namespace = Namespace
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetPod(Pod *corev1.Pod) *Resolution {
	resolution.Lock()
	resolution.Pod = Pod
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetEndpointSlice(EndpointSlice *corev1.Endpoints) *Resolution {
	resolution.Lock()
	resolution.EndpointSlice = EndpointSlice
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetService(Service *corev1.Service) *Resolution {
	resolution.Lock()
	resolution.Service = Service
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetCgroupID(CgroupID uint) *Resolution {
	resolution.Lock()
	resolution.CgroupID = CgroupID
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetContainerID(ContainerID string) *Resolution {
	resolution.Lock()
	resolution.ContainerID = ContainerID
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetSocketID(SocketID uint) *Resolution {
	resolution.Lock()
	resolution.SocketID = SocketID
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetProcessID(ProcessID int) *Resolution {
	resolution.Lock()
	resolution.ProcessID = ProcessID
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetParentProcessID(ParentProcessID int) *Resolution {
	resolution.Lock()
	resolution.ParentProcessID = ParentProcessID
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetHostProcessID(HostProcessID int) *Resolution {
	resolution.Lock()
	resolution.HostProcessID = HostProcessID
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetHostParentProcessID(HostParentProcessID int) *Resolution {
	resolution.Lock()
	resolution.HostParentProcessID = HostParentProcessID
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetProcessName(ProcessName string) *Resolution {
	resolution.Lock()
	resolution.ProcessName = ProcessName
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetProcessPath(ProcessPath string) *Resolution {
	resolution.Lock()
	resolution.ProcessPath = ProcessPath
	resolution.Unlock()
	return resolution
}

func (resolution *Resolution) SetResolutionMechanism(ResolutionMechanism ResolutionMechanism) *Resolution {
	resolution.Lock()
	resolution.ResolutionMechanism = ResolutionMechanism
	resolution.Unlock()
	return resolution
}

func (r *Resolution) New() *Resolution {
	r.Lock()
	newR := &Resolution{
		IP:                  r.IP,
		Port:                r.Port,
		Name:                r.Name,
		Namespace:           r.Namespace,
		Pod:                 r.Pod,
		EndpointSlice:       r.EndpointSlice,
		Service:             r.Service,
		ResolutionMechanism: r.ResolutionMechanism,
	}
	r.Unlock()

	return newR
}

type ObjectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type SpecSummary struct {
	NodeName string `json:"nodeName"`
}

type StatusSummary struct {
	HostIP string `json:"hostIp"`
}

type PodSummary struct {
	Metadata *ObjectMeta    `json:"metadata"`
	Spec     *SpecSummary   `json:"spec"`
	Status   *StatusSummary `json:"status"`
}

type Object struct {
	Metadata *ObjectMeta `json:"metadata"`
}

type ResolutionSummary struct {
	IP                  string              `json:"ip"`
	Port                string              `json:"port"`
	Name                string              `json:"name"`
	Namespace           string              `json:"namespace"`
	Pod                 *PodSummary         `json:"pod"`
	EndpointSlice       *Object             `json:"endpointSlice"`
	Service             *Object             `json:"service"`
	CgroupID            uint                `json:"cgroupId"`
	ContainerID         string              `json:"containerId"`
	SocketID            uint                `json:"socketId"`
	ProcessID           int                 `json:"processId"`
	ParentProcessID     int                 `json:"parentProcessId"`
	HostProcessID       int                 `json:"hostProcessId"`
	HostParentProcessID int                 `json:"hostParentProcessId"`
	ProcessName         string              `json:"processName"`
	ResolutionMechanism ResolutionMechanism `json:"resolutionMechanism"`
}

type Extension struct {
	Protocol  *Protocol
	Path      string
	Dissector Dissector
}

type VLAN struct {
	ID    uint16 `json:"id"`
	Dot1Q bool   `json:"dot1q"`
}

type Proxy struct {
	Name string `json:"name"`
	Pid  string `json:"pid"`
}

type Capture struct {
	Backend string `json:"backend"`
	Source  string `json:"source"`
	Proxy   *Proxy `json:"proxy"`
	VLAN    *VLAN  `json:"vlan"`
}

type ConnectionInfo struct {
	ClientIP       string
	ClientPort     string
	ClientCgroupID uint64
	ServerIP       string
	ServerPort     string
	ServerCgroupID uint64
	IsOutgoing     bool
	IsKubeProbe    bool
	ContainerId    string
	sync.Mutex
}

func (connectioninfo *ConnectionInfo) GetClientIP() string {
	connectioninfo.Lock()
	clientip := connectioninfo.ClientIP
	connectioninfo.Unlock()
	return clientip
}

func (connectioninfo *ConnectionInfo) GetClientPort() string {
	connectioninfo.Lock()
	clientport := connectioninfo.ClientPort
	connectioninfo.Unlock()
	return clientport
}

func (connectioninfo *ConnectionInfo) GetClientCgroupID() uint64 {
	connectioninfo.Lock()
	clientcgroupid := connectioninfo.ClientCgroupID
	connectioninfo.Unlock()
	return clientcgroupid
}

func (connectioninfo *ConnectionInfo) GetServerIP() string {
	connectioninfo.Lock()
	serverip := connectioninfo.ServerIP
	connectioninfo.Unlock()
	return serverip
}

func (connectioninfo *ConnectionInfo) GetServerPort() string {
	connectioninfo.Lock()
	serverport := connectioninfo.ServerPort
	connectioninfo.Unlock()
	return serverport
}

func (connectioninfo *ConnectionInfo) GetServerCgroupID() uint64 {
	connectioninfo.Lock()
	servercgroupid := connectioninfo.ServerCgroupID
	connectioninfo.Unlock()
	return servercgroupid
}

func (connectioninfo *ConnectionInfo) GetIsOutgoing() bool {
	connectioninfo.Lock()
	isoutgoing := connectioninfo.IsOutgoing
	connectioninfo.Unlock()
	return isoutgoing
}

func (connectioninfo *ConnectionInfo) GetIsKubeProbe() bool {
	connectioninfo.Lock()
	iskubeprobe := connectioninfo.IsKubeProbe
	connectioninfo.Unlock()
	return iskubeprobe
}

func (connectioninfo *ConnectionInfo) GetContainerId() string {
	connectioninfo.Lock()
	containerid := connectioninfo.ContainerId
	connectioninfo.Unlock()
	return containerid
}

func (connectioninfo *ConnectionInfo) SetClientIP(ClientIP string) *ConnectionInfo {
	connectioninfo.Lock()
	connectioninfo.ClientIP = ClientIP
	connectioninfo.Unlock()
	return connectioninfo
}

func (connectioninfo *ConnectionInfo) SetClientPort(ClientPort string) *ConnectionInfo {
	connectioninfo.Lock()
	connectioninfo.ClientPort = ClientPort
	connectioninfo.Unlock()
	return connectioninfo
}

func (connectioninfo *ConnectionInfo) SetClientCgroupID(ClientCgroupID uint64) *ConnectionInfo {
	connectioninfo.Lock()
	connectioninfo.ClientCgroupID = ClientCgroupID
	connectioninfo.Unlock()
	return connectioninfo
}

func (connectioninfo *ConnectionInfo) SetServerIP(ServerIP string) *ConnectionInfo {
	connectioninfo.Lock()
	connectioninfo.ServerIP = ServerIP
	connectioninfo.Unlock()
	return connectioninfo
}

func (connectioninfo *ConnectionInfo) SetServerPort(ServerPort string) *ConnectionInfo {
	connectioninfo.Lock()
	connectioninfo.ServerPort = ServerPort
	connectioninfo.Unlock()
	return connectioninfo
}

func (connectioninfo *ConnectionInfo) SetServerCgroupID(ServerCgroupID uint64) *ConnectionInfo {
	connectioninfo.Lock()
	connectioninfo.ServerCgroupID = ServerCgroupID
	connectioninfo.Unlock()
	return connectioninfo
}

func (connectioninfo *ConnectionInfo) SetIsOutgoing(IsOutgoing bool) *ConnectionInfo {
	connectioninfo.Lock()
	connectioninfo.IsOutgoing = IsOutgoing
	connectioninfo.Unlock()
	return connectioninfo
}

func (connectioninfo *ConnectionInfo) SetIsKubeProbe(IsKubeProbe bool) *ConnectionInfo {
	connectioninfo.Lock()
	connectioninfo.IsKubeProbe = IsKubeProbe
	connectioninfo.Unlock()
	return connectioninfo
}

func (connectioninfo *ConnectionInfo) SetContainerId(ContainerId string) *ConnectionInfo {
	connectioninfo.Lock()
	connectioninfo.ContainerId = ContainerId
	connectioninfo.Unlock()
	return connectioninfo
}

type TcpID struct {
	SrcIP       string
	DstIP       string
	SrcPort     string
	DstPort     string
	SrcCgroupID uint64
	DstCgroupID uint64
	Ident       string
	sync.Mutex
}

func (tcpid *TcpID) GetSrcIP() string {
	tcpid.Lock()
	srcIP := tcpid.SrcIP
	tcpid.Unlock()
	return srcIP
}

func (tcpid *TcpID) GetDstIP() string {
	tcpid.Lock()
	dstIP := tcpid.DstIP
	tcpid.Unlock()
	return dstIP
}

func (tcpid *TcpID) GetSrcPort() string {
	tcpid.Lock()
	srcPort := tcpid.SrcPort
	tcpid.Unlock()
	return srcPort
}

func (tcpid *TcpID) GetDstPort() string {
	tcpid.Lock()
	dstPort := tcpid.DstPort
	tcpid.Unlock()
	return dstPort
}

func (tcpid *TcpID) GetSrcCgroupID() uint64 {
	tcpid.Lock()
	srcCgroupID := tcpid.SrcCgroupID
	tcpid.Unlock()
	return srcCgroupID
}

func (tcpid *TcpID) GetDstCgroupID() uint64 {
	tcpid.Lock()
	dstCgroupID := tcpid.DstCgroupID
	tcpid.Unlock()
	return dstCgroupID
}

func (tcpid *TcpID) GetIdent() string {
	tcpid.Lock()
	ident := tcpid.Ident
	tcpid.Unlock()
	return ident
}

func (tcpid *TcpID) SetSrcIP(SrcIP string) *TcpID {
	tcpid.Lock()
	tcpid.SrcIP = SrcIP
	tcpid.Unlock()
	return tcpid
}

func (tcpid *TcpID) SetDstIP(DstIP string) *TcpID {
	tcpid.Lock()
	tcpid.DstIP = DstIP
	tcpid.Unlock()
	return tcpid
}

func (tcpid *TcpID) SetSrcPort(SrcPort string) *TcpID {
	tcpid.Lock()
	tcpid.SrcPort = SrcPort
	tcpid.Unlock()
	return tcpid
}

func (tcpid *TcpID) SetDstPort(DstPort string) *TcpID {
	tcpid.Lock()
	tcpid.DstPort = DstPort
	tcpid.Unlock()
	return tcpid
}

func (tcpid *TcpID) SetSrcCgroupID(SrcCgroupID uint64) *TcpID {
	tcpid.Lock()
	tcpid.SrcCgroupID = SrcCgroupID
	tcpid.Unlock()
	return tcpid
}

func (tcpid *TcpID) SetDstCgroupID(DstCgroupID uint64) *TcpID {
	tcpid.Lock()
	tcpid.DstCgroupID = DstCgroupID
	tcpid.Unlock()
	return tcpid
}

func (tcpid *TcpID) SetIdent(Ident string) *TcpID {
	tcpid.Lock()
	tcpid.Ident = Ident
	tcpid.Unlock()
	return tcpid
}

type CounterPair struct {
	Request  uint
	Response uint
	sync.Mutex
}

type GenericMessage struct {
	IsRequest   bool
	CaptureTime time.Time
	CaptureSize int
	Payload     interface{}
	IsKubeProbe bool
}

type RequestResponsePair struct {
	Request  *GenericMessage
	Response *GenericMessage
}

// {Stream}-{Index} uniquely identifies an item
// `Protocol` is modified in later stages of data propagation. Therefore, it's not a pointer.
type OutputChannelItem struct {
	Index          int64
	Stream         string
	Protocol       Protocol
	Timestamp      int64
	ConnectionInfo *ConnectionInfo
	Pair           *RequestResponsePair
	Data           *GenericMessage
	Tls            bool
	Error          *Error
	Capture        *Capture
	Checksums      []string
}

type ReadProgress struct {
	readBytes      int
	lastCheckpoint int
	sync.Mutex
}

func (p *ReadProgress) Feed(n int) {
	p.Lock()
	p.readBytes += n
	p.Unlock()
}

func (p *ReadProgress) Current() (n int) {
	p.Lock()
	current := p.readBytes - p.lastCheckpoint
	p.lastCheckpoint = p.readBytes
	p.Unlock()
	return current
}

func (p *ReadProgress) Reset() {
	p.Lock()
	p.readBytes = 0
	p.lastCheckpoint = 0
	p.Unlock()
}

type Dissector interface {
	Register(*Extension)
	Dissect(b *bufio.Reader, reader TcpReader) (err error)
	Analyze(item *OutputChannelItem, resolvedSource *Resolution, resolvedDestination *Resolution) *Entry
	Summarize(entry *Entry) *BaseEntry
	Represent(request interface{}, response interface{}, event *Event, data interface{}) (representation *Representation)
	Macros() map[string]string
	NewResponseRequestMatcher() RequestResponseMatcher
	Typed(data []byte, requestRef string, responseRef string, eventRef string, dataRef string) (request interface{}, response interface{}, event *Event, dataValue interface{}, err error)
}

type RequestResponseMatcher interface {
	GetMap() *sync.Map
	SetMaxTry(value int)
	GetLastRequest() *GenericMessage
	GetLastResponse() *GenericMessage
}

type Emitting struct {
	AppStats      *AppStats
	Stream        TcpStream
	OutputChannel chan *OutputChannelItem
}

type Emitter interface {
	Emit(item *OutputChannelItem)
}

func (e *Emitting) Emit(item *OutputChannelItem) {
	e.AppStats.IncMatchedPairs()

	item.Stream = e.Stream.GetPcapId()
	item.Index = e.Stream.GetIndex()
	item.Tls = e.Stream.GetTls()
	e.Stream.IncrementItemCount()
	e.OutputChannel <- item
}

type Node struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

type ErrorType int

const (
	DissectionError ErrorType = iota
	ConnectionError
	TimeoutError
	PairNotFoundError
)

type Error struct {
	Type    ErrorType `json:"type"`
	Message string    `json:"msg"`
}

func (e *ErrorType) MarshalJSON() ([]byte, error) {
	var val string
	switch *e {
	case DissectionError:
		val = "dissection"
	case ConnectionError:
		val = "connection"
	case TimeoutError:
		val = "timeout"
	case PairNotFoundError:
		val = "pair-not-found"
	default:
		return []byte{}, errors.New("the error type is unknown")
	}

	return json.Marshal(val)
}

func (e *ErrorType) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	switch s {
	case "dissection":
		*e = DissectionError
	case "connection":
		*e = ConnectionError
	case "timeout":
		*e = TimeoutError
	case "pair-not-found":
		*e = PairNotFoundError
	default:
		return errors.New("the error type is unknown")
	}

	return nil
}

type Event struct {
	Source string      `json:"source"`
	Type   string      `json:"type"`
	Data   interface{} `json:"data"`
}

// {Worker}/{Stream}-{Index} uniquely identifies an item
type Entry struct {
	Id           string      `json:"id"`
	Index        int64       `json:"index"`
	Stream       string      `json:"stream"`
	Worker       string      `json:"worker"`
	Node         *Node       `json:"node"`
	Protocol     Protocol    `json:"protocol"`
	Tls          bool        `json:"tls"`
	Source       *Resolution `json:"src"`
	Destination  *Resolution `json:"dst"`
	Outgoing     bool        `json:"outgoing"`
	Timestamp    int64       `json:"timestamp"`
	StartTime    time.Time   `json:"startTime"`
	Request      interface{} `json:"request"`
	Response     interface{} `json:"response"`
	RequestRef   string      `json:"requestRef"`
	ResponseRef  string      `json:"responseRef"`
	RequestSize  int         `json:"requestSize"`
	ResponseSize int         `json:"responseSize"`
	ElapsedTime  int64       `json:"elapsedTime"`
	Passed       bool        `json:"passed"`
	Failed       bool        `json:"failed"`
	Error        *Error      `json:"error"`
	EntryFile    string      `json:"entryFile"`
	Record       string      `json:"record"`
	Event        *Event      `json:"event"`
	EventRef     string      `json:"eventRef"`
	Base         *BaseEntry  `json:"base"`
	Capture      *Capture    `json:"capture"`
	Checksums    []string    `json:"checksums"`
	Duplicate    string      `json:"duplicate"`
	Data         interface{} `json:"data"`
	DataRef      string      `json:"dataRef"`
	Size         int         `json:"size"`
}

func (e *Entry) BuildId() {
	e.Id = fmt.Sprintf("%s/%s-%d", e.Worker, e.Stream, e.Index)
}

func (e *Entry) BuildFilenames() {
	e.EntryFile = GetEntryFile(e.Stream, e.Index)
}

func (e *Entry) SourceSummary() *ResolutionSummary {
	if e.Source == nil {
		return &ResolutionSummary{}
	}

	s := &ResolutionSummary{
		IP:                  e.Source.IP,
		Port:                e.Source.Port,
		Name:                e.Source.Name,
		Namespace:           e.Source.Namespace,
		CgroupID:            e.Source.CgroupID,
		ContainerID:         e.Source.ContainerID,
		SocketID:            e.Source.SocketID,
		ProcessID:           e.Source.ProcessID,
		ParentProcessID:     e.Source.ParentProcessID,
		HostProcessID:       e.Source.HostProcessID,
		HostParentProcessID: e.Source.HostParentProcessID,
		ProcessName:         e.Source.ProcessName,
		ResolutionMechanism: e.Source.ResolutionMechanism,
	}

	if e.Source.Pod != nil {
		s.Pod = &PodSummary{
			Metadata: &ObjectMeta{
				Name:      e.Source.Pod.ObjectMeta.Name,
				Namespace: e.Source.Pod.ObjectMeta.Namespace,
			},
			Spec: &SpecSummary{
				NodeName: e.Source.Pod.Spec.NodeName,
			},
			Status: &StatusSummary{
				HostIP: e.Source.Pod.Status.HostIP,
			},
		}
	}

	if e.Source.EndpointSlice != nil {
		s.EndpointSlice = &Object{
			Metadata: &ObjectMeta{
				Name:      e.Source.EndpointSlice.ObjectMeta.Name,
				Namespace: e.Source.EndpointSlice.ObjectMeta.Namespace,
			},
		}
	}

	if e.Source.Service != nil {
		s.Service = &Object{
			Metadata: &ObjectMeta{
				Name:      e.Source.Service.ObjectMeta.Name,
				Namespace: e.Source.Service.ObjectMeta.Namespace,
			},
		}
	}

	return s
}

func (e *Entry) DestinationSummary() *ResolutionSummary {
	if e.Destination == nil {
		return &ResolutionSummary{}
	}

	s := &ResolutionSummary{
		IP:                  e.Destination.IP,
		Port:                e.Destination.Port,
		Name:                e.Destination.Name,
		Namespace:           e.Destination.Namespace,
		CgroupID:            e.Destination.CgroupID,
		ContainerID:         e.Destination.ContainerID,
		SocketID:            e.Destination.SocketID,
		ProcessID:           e.Destination.ProcessID,
		ParentProcessID:     e.Destination.ParentProcessID,
		HostProcessID:       e.Destination.HostProcessID,
		HostParentProcessID: e.Source.HostParentProcessID,
		ProcessName:         e.Destination.ProcessName,
		ResolutionMechanism: e.Destination.ResolutionMechanism,
	}

	if e.Destination.Pod != nil {
		s.Pod = &PodSummary{
			Metadata: &ObjectMeta{
				Name:      e.Destination.Pod.ObjectMeta.Name,
				Namespace: e.Destination.Pod.ObjectMeta.Namespace,
			},
			Spec: &SpecSummary{
				NodeName: e.Destination.Pod.Spec.NodeName,
			},
			Status: &StatusSummary{
				HostIP: e.Destination.Pod.Status.HostIP,
			},
		}
	}

	if e.Destination.EndpointSlice != nil {
		s.EndpointSlice = &Object{
			Metadata: &ObjectMeta{
				Name:      e.Destination.EndpointSlice.ObjectMeta.Name,
				Namespace: e.Destination.EndpointSlice.ObjectMeta.Namespace,
			},
		}
	}

	if e.Destination.Service != nil {
		s.Service = &Object{
			Metadata: &ObjectMeta{
				Name:      e.Destination.Service.ObjectMeta.Name,
				Namespace: e.Destination.Service.ObjectMeta.Namespace,
			},
		}
	}

	return s
}

type Representation struct {
	Request  []*SectionData `json:"request"`
	Response []*SectionData `json:"response"`
	Event    []*SectionData `json:"event"`
	Data     []*SectionData `json:"data"`
}

type EntryWrapper struct {
	Protocol       Protocol        `json:"protocol"`
	Representation *Representation `json:"representation"`
	Data           *Entry          `json:"data"`
	Base           *BaseEntry      `json:"base"`
}

// {Worker}/{Id} uniquely identifies an item
type BaseEntry struct {
	Id           string             `json:"id"`
	Stream       string             `json:"stream"`
	Worker       string             `json:"worker"`
	Protocol     Protocol           `json:"proto,omitempty"`
	Tls          bool               `json:"tls"`
	Summary      string             `json:"summary,omitempty"`
	SummaryQuery string             `json:"summaryQuery,omitempty"`
	Status       int                `json:"status"`
	StatusQuery  string             `json:"statusQuery"`
	Method       string             `json:"method,omitempty"`
	MethodQuery  string             `json:"methodQuery,omitempty"`
	Timestamp    int64              `json:"timestamp,omitempty"`
	Source       *ResolutionSummary `json:"src"`
	Destination  *ResolutionSummary `json:"dst"`
	Outgoing     bool               `json:"outgoing"`
	RequestSize  int                `json:"requestSize"`
	ResponseSize int                `json:"responseSize"`
	ElapsedTime  int64              `json:"elapsedTime"`
	Passed       bool               `json:"passed"`
	Failed       bool               `json:"failed"`
	Error        *Error             `json:"error"`
	Record       string             `json:"record"`
	Event        bool               `json:"event"`
	Capture      *Capture           `json:"capture"`
	Checksums    []string           `json:"checksums"`
	Duplicate    string             `json:"duplicate"`
	Size         int                `json:"size"`
}

const (
	TABLE string = "table"
	BODY  string = "body"
)

type SectionData struct {
	Type      string       `json:"type"`
	Title     string       `json:"title"`
	TableData []*TableData `json:"tableData"`
	Encoding  string       `json:"encoding,omitempty"`
	MimeType  string       `json:"mimeType,omitempty"`
	Body      string       `json:"body"`
	Selector  string       `json:"selector,omitempty"`
}

type TableData struct {
	Name     string      `json:"name"`
	Value    interface{} `json:"value"`
	Selector string      `json:"selector"`
}

type TcpReaderDataMsg interface {
	GetBytes() []byte
	GetTimestamp() time.Time
	GetCaptureInfo() gopacket.CaptureInfo
}

type TcpReader interface {
	Read(p []byte) (int, error)
	GetReqResMatcher() RequestResponseMatcher
	GetIsClient() bool
	GetReadProgress() *ReadProgress
	GetParent() TcpStream
	GetTcpID() *TcpID
	GetCounterPair() *CounterPair
	GetCaptureTime() time.Time
	GetEmitter() Emitter
	GetIsClosed() bool
	GetCapture() *Capture
	Rewind()
}

type TcpStream interface {
	SetProtocol(protocol *Protocol)
	GetPcapId() string
	GetIndex() int64
	GetReqResMatchers() []RequestResponseMatcher
	GetIsClosed() bool
	IncrementItemCount()
	GetTls() bool
	GetCapture() *Capture
	GetChecksums() []string
}

type TcpStreamMap interface {
	Range(f func(key, value interface{}) bool)
	Store(key, value interface{})
	Delete(key interface{})
	NextId() int64
	Close()
	CloseTimedoutTcpStreamChannels()
}
