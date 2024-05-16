package api

import (
	"bufio"
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

type Resolution struct {
	IP            string            `json:"ip"`
	Port          string            `json:"port"`
	Name          string            `json:"name"`
	Namespace     string            `json:"namespace"`
	Pod           *corev1.Pod       `json:"pod"`
	EndpointSlice *corev1.Endpoints `json:"endpointSlice"`
	Service       *corev1.Service   `json:"service"`
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
	IP            string      `json:"ip"`
	Port          string      `json:"port"`
	Name          string      `json:"name"`
	Namespace     string      `json:"namespace"`
	Pod           *PodSummary `json:"pod"`
	EndpointSlice *Object     `json:"endpointSlice"`
	Service       *Object     `json:"service"`
}

type Extension struct {
	Protocol  *Protocol
	Path      string
	Dissector Dissector
}

type ConnectionInfo struct {
	ClientIP       string
	ClientPort     string
	ClientCgroupID uint64
	ServerIP       string
	ServerPort     string
	ServerCgroupID uint64
	IsOutgoing     bool
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
	IsRequest   bool        `json:"isRequest"`
	CaptureTime time.Time   `json:"captureTime"`
	CaptureSize int         `json:"captureSize"`
	Payload     interface{} `json:"payload"`
}

type RequestResponsePair struct {
	Request  *GenericMessage `json:"request"`
	Response *GenericMessage `json:"response"`
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
	Tls            bool
	Error          *Error
}

type ReadProgress struct {
	readBytes   int
	lastCurrent int
}

func (p *ReadProgress) Feed(n int) {
	p.readBytes += n
}

func (p *ReadProgress) Current() (n int) {
	p.lastCurrent = p.readBytes - p.lastCurrent
	return p.lastCurrent
}

func (p *ReadProgress) Reset() {
	p.readBytes = 0
	p.lastCurrent = 0
}

type Dissector interface {
	Register(*Extension)
	Dissect(b *bufio.Reader, reader TcpReader) (err error)
	Analyze(item *OutputChannelItem, resolvedSource *Resolution, resolvedDestination *Resolution) *Entry
	Summarize(entry *Entry) *BaseEntry
	Represent(request interface{}, response interface{}, event *Event) (representation []*SectionData, err error)
	Macros() map[string]string
	NewResponseRequestMatcher() RequestResponseMatcher
	Typed(data []byte, requestRef string, responseRef string, eventRef string) (request interface{}, response interface{}, event *Event, err error)
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
)

type Error struct {
	Type    ErrorType `json:"type"`
	Message string    `json:"msg"`
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
}

func (e *Entry) BuildId() {
	e.Id = fmt.Sprintf("%s/%s-%d", e.Worker, e.Stream, e.Index)
}

func (e *Entry) BuildFilenames() {
	e.EntryFile = GetEntryFile(e.Stream, e.Index)
}

func (e *Entry) SourceSummary() *ResolutionSummary {
	s := &ResolutionSummary{
		IP:        e.Source.IP,
		Port:      e.Source.Port,
		Name:      e.Source.Name,
		Namespace: e.Source.Namespace,
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
	s := &ResolutionSummary{
		IP:        e.Destination.IP,
		Port:      e.Destination.Port,
		Name:      e.Destination.Name,
		Namespace: e.Destination.Namespace,
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

type EntryWrapper struct {
	Protocol       Protocol       `json:"protocol"`
	Representation []*SectionData `json:"representation"`
	Data           *Entry         `json:"data"`
	Base           *BaseEntry     `json:"base"`
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
}

const (
	TABLE string = "table"
	BODY  string = "body"
)

type SectionData struct {
	Type     string      `json:"type"`
	Title    string      `json:"title"`
	Data     interface{} `json:"data"`
	Encoding string      `json:"encoding,omitempty"`
	MimeType string      `json:"mimeType,omitempty"`
	Selector string      `json:"selector,omitempty"`
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
}

type TcpStream interface {
	SetProtocol(protocol *Protocol)
	GetPcapId() string
	GetIndex() int64
	GetReqResMatchers() []RequestResponseMatcher
	GetIsClosed() bool
	IncrementItemCount()
	GetTls() bool
}

type TcpStreamMap interface {
	Range(f func(key, value interface{}) bool)
	Store(key, value interface{})
	Delete(key interface{})
	NextId() int64
	Close()
	CloseTimedoutTcpStreamChannels()
}
