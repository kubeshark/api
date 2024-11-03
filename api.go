package api

import (
	"bufio"
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
	ResolutionMechanism ResolutionMechanism `json:"resolutionMechanism"`
}

func (r *Resolution) New() *Resolution {
	return &Resolution{
		IP:                  r.IP,
		Port:                r.Port,
		Name:                r.Name,
		Namespace:           r.Namespace,
		Pod:                 r.Pod,
		EndpointSlice:       r.EndpointSlice,
		Service:             r.Service,
		ResolutionMechanism: r.ResolutionMechanism,
	}
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
}

type TcpID struct {
	SrcIP       string
	DstIP       string
	SrcPort     string
	DstPort     string
	SrcCgroupID uint64
	DstCgroupID uint64
	Ident       string
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
	FailedRequestError
)

type Error struct {
	Type    ErrorType `json:"type"`
	Message string    `json:"msg"`
}

func (e *ErrorType) MarshalJSON() ([]byte, error) {
	var val []byte
	switch *e {
	case DissectionError:
		val = []byte("dissection")
	case ConnectionError:
		val = []byte("connection")
	case TimeoutError:
		val = []byte("timeout")
	case PairNotFoundError:
		val = []byte("pair-not-found")
	case FailedRequestError:
		val = []byte("failed-request")
	default:
		return val, errors.New("the error type is unknown")
	}

	return val, nil
}

func (e *ErrorType) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case "dissection":
		*e = DissectionError
	case "connection":
		*e = ConnectionError
	case "timeout":
		*e = TimeoutError
	case "pair-not-found":
		*e = PairNotFoundError
	case "failed-request":
		*e = FailedRequestError
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
