package api

import (
	"sync"
	"sync/atomic"
	"time"
)

type AppStats struct {
	StartTime                   time.Time `json:"-"`
	ProcessedBytes              uint64    `json:"processedBytes"`
	PacketsCount                uint64    `json:"packetsCount"`
	TcpPacketsCount             uint64    `json:"tcpPacketsCount"`
	UdpPacketsCount             uint64    `json:"udpPacketsCount"`
	IcmpPacketsCount            uint64    `json:"icmpPacketsCount"`
	SctpPacketsCount            uint64    `json:"sctpPacketsCount"`
	ReassembledTcpPayloadsCount uint64    `json:"reassembledTcpPayloadsCount"`
	MatchedPairs                uint64    `json:"matchedPairs"`
	DroppedTcpStreams           uint64    `json:"droppedTcpStreams"`
	LiveTcpStreams              uint64    `json:"liveTcpStreams"`
	TlsPacketCount              uint64    `json:"tlsPacketCount"`
	TlsPacketDropped            uint64    `json:"tlsPacketDropped"`
	ItemCount                   uint64    `json:"itemCount"`
	WsItemWriteCount            uint64    `json:"wsItemWriteCount"`
	sync.Mutex
}

func (as *AppStats) IncMatchedPairs() {
	atomic.AddUint64(&as.MatchedPairs, 1)
}

func (as *AppStats) IncDroppedTcpStreams() {
	atomic.AddUint64(&as.DroppedTcpStreams, 1)
}

func (as *AppStats) IncPacketsCount() uint64 {
	atomic.AddUint64(&as.PacketsCount, 1)
	return atomic.LoadUint64(&as.PacketsCount)
}

func (as *AppStats) IncTcpPacketsCount() {
	atomic.AddUint64(&as.TcpPacketsCount, 1)
}

func (as *AppStats) IncUdpPacketsCount() {
	atomic.AddUint64(&as.UdpPacketsCount, 1)
}

func (as *AppStats) IncIcmpPacketsCount() {
	atomic.AddUint64(&as.IcmpPacketsCount, 1)
}

func (as *AppStats) IncSctpPacketsCount() {
	atomic.AddUint64(&as.SctpPacketsCount, 1)
}

func (as *AppStats) IncReassembledTcpPayloadsCount() {
	atomic.AddUint64(&as.ReassembledTcpPayloadsCount, 1)
}

func (as *AppStats) IncLiveTcpStreams() {
	atomic.AddUint64(&as.LiveTcpStreams, 1)
}

func (as *AppStats) DecLiveTcpStreams() {
	atomic.AddUint64(&as.LiveTcpStreams, ^uint64(0))
}

func (as *AppStats) UpdateProcessedBytes(size uint64) {
	atomic.AddUint64(&as.ProcessedBytes, size)
}

func (as *AppStats) SetStartTime(startTime time.Time) {
	as.Lock()
	as.StartTime = startTime
	as.Unlock()
}

func (as *AppStats) IncTlsPacketCount() {
	atomic.AddUint64(&as.TlsPacketCount, 1)
}

func (as *AppStats) IncTlsPacketDropped(size uint64) {
	atomic.AddUint64(&as.TlsPacketDropped, size)
}

func (as *AppStats) IncItemCount() {
	atomic.AddUint64(&as.ItemCount, 1)
}

func (as *AppStats) IncWsItemWriteCount() {
	atomic.AddUint64(&as.WsItemWriteCount, 1)
}

func (as *AppStats) DumpStats() *AppStats {
	as.Lock()
	currentAppStats := &AppStats{StartTime: as.StartTime}
	as.Unlock()

	currentAppStats.ProcessedBytes = resetUint64(&as.ProcessedBytes)
	currentAppStats.PacketsCount = resetUint64(&as.PacketsCount)
	currentAppStats.TcpPacketsCount = resetUint64(&as.TcpPacketsCount)
	currentAppStats.UdpPacketsCount = resetUint64(&as.UdpPacketsCount)
	currentAppStats.IcmpPacketsCount = resetUint64(&as.IcmpPacketsCount)
	currentAppStats.SctpPacketsCount = resetUint64(&as.SctpPacketsCount)
	currentAppStats.ReassembledTcpPayloadsCount = resetUint64(&as.ReassembledTcpPayloadsCount)
	currentAppStats.MatchedPairs = resetUint64(&as.MatchedPairs)
	currentAppStats.DroppedTcpStreams = resetUint64(&as.DroppedTcpStreams)
	currentAppStats.LiveTcpStreams = resetUint64(&as.LiveTcpStreams)
	currentAppStats.TlsPacketCount = resetUint64(&as.TlsPacketCount)
	currentAppStats.TlsPacketDropped = resetUint64(&as.TlsPacketDropped)
	currentAppStats.ItemCount = resetUint64(&as.ItemCount)
	currentAppStats.WsItemWriteCount = resetUint64(&as.WsItemWriteCount)
	return currentAppStats
}

func resetUint64(ref *uint64) (val uint64) {
	val = atomic.LoadUint64(ref)
	// TODO: Temporarily disabled
	// atomic.StoreUint64(ref, 0)
	return
}
