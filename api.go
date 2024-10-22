package api

import (
	"bufio"
	"fmt"
	"sync"
	"time"

	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/kubeshark/gopacket"
)

func (r *Resolution) New() *Resolution {
	return &Resolution{
		Ip:                  r.Ip,
		Port:                r.Port,
		Name:                r.Name,
		Namespace:           r.Namespace,
		Pod:                 r.Pod,
		EndpointSlice:       r.EndpointSlice,
		Service:             r.Service,
		ResolutionMechanism: r.ResolutionMechanism,
	}
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
	Protocol       *Protocol
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
	Represent(request *structpb.Struct, response *structpb.Struct, event *Event, data *structpb.Struct) (representation *Representation)
	Macros() map[string]string
	NewResponseRequestMatcher() RequestResponseMatcher
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

func (e *Entry) BuildId() {
	e.Id = fmt.Sprintf("%s/%s-%d", e.GetWorker(), e.GetStream(), e.GetIndex())
}

func (e *Entry) BuildFilenames() {
	e.EntryFile = GetEntryFile(e.GetStream(), e.GetIndex())
}

const (
	TABLE string = "table"
	BODY  string = "body"
)

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
