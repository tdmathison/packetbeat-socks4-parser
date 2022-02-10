// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package socks4

import (
	"time"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
)

// socks4Plugin application level protocol analyzer plugin
type socks4Plugin struct {
	ports        protos.PortsConfig
	parserConfig parserConfig
	transConfig  transactionConfig
	watcher      procs.ProcessesWatcher
	pub          transPub
}

// Application Layer tcp stream data to be stored on tcp connection context.
type connection struct {
	streams [2]*stream
	trans   transactions
}

// Uni-directional tcp stream state for parsing messages.
type stream struct {
	parser parser
}

var (
	debugf = logp.MakeDebug("socks4")

	// use isDebug/isDetailed to guard debugf/detailedf to minimize allocations
	// (garbage collection) when debug log is disabled.
	isDebug = false
)

func init() {
	protos.Register("socks4", New)
}

// New create and initializes a new socks4 protocol analyzer instance.
func New(
	testMode bool,
	results protos.Reporter,
	watcher procs.ProcessesWatcher,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &socks4Plugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, watcher, &config); err != nil {
		return nil, err
	}
	return p, nil
}

func (sp *socks4Plugin) init(results protos.Reporter, watcher procs.ProcessesWatcher, config *socks4Config) error {
	if err := sp.setFromConfig(config); err != nil {
		return err
	}
	sp.pub.results = results
	sp.watcher = watcher

	isDebug = logp.IsDebug("http")
	return nil
}

func (sp *socks4Plugin) setFromConfig(config *socks4Config) error {

	// set module configuration
	if err := sp.ports.Set(config.Ports); err != nil {
		return err
	}

	// set parser configuration
	parser := &sp.parserConfig
	parser.maxBytes = tcp.TCPMaxDataInStream

	// set transaction correlator configuration
	trans := &sp.transConfig
	trans.transactionTimeout = config.TransactionTimeout

	// set transaction publisher configuration
	pub := &sp.pub
	pub.sendRequest = config.SendRequest
	pub.sendResponse = config.SendResponse

	return nil
}

// ConnectionTimeout returns the per stream connection timeout.
// Return <=0 to set default tcp module transaction timeout.
func (sp *socks4Plugin) ConnectionTimeout() time.Duration {
	return sp.transConfig.transactionTimeout
}

// GetPorts returns the ports numbers packets shall be processed for.
func (sp *socks4Plugin) GetPorts() []int {
	return sp.ports.Ports
}

// Parse processes a TCP packet. Return nil if connection
// state shall be dropped (e.g. parser not in sync with tcp stream)
func (sp *socks4Plugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("Parse socks4Plugin exception")

	conn := sp.ensureConnection(private)
	st := conn.streams[dir]
	if st == nil {
		st = &stream{}
		st.parser.init(&sp.parserConfig, func(msg *message) error {
			return conn.trans.onMessage(tcptuple.IPPort(), dir, msg)
		})
		conn.streams[dir] = st
	}

	// Feeds the packets timestamp and payload into the parser
	if err := st.parser.feed(pkt.Ts, pkt.Payload); err != nil {
		//debugf("%v, dropping TCP stream for error in direction %v.", err, dir)
		sp.onDropConnection(conn)
		return nil
	}
	return conn
}

// ReceivedFin handles TCP-FIN packet.
func (sp *socks4Plugin) ReceivedFin(
	tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	return private
}

// GapInStream handles lost packets in tcp-stream.
func (sp *socks4Plugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int,
	private protos.ProtocolData,
) (protos.ProtocolData, bool) {
	conn := getConnection(private)
	if conn != nil {
		sp.onDropConnection(conn)
	}

	return nil, true
}

// onDropConnection processes and optionally sends incomplete
// transaction in case of connection being dropped due to error
func (sp *socks4Plugin) onDropConnection(conn *connection) {
}

func (sp *socks4Plugin) ensureConnection(private protos.ProtocolData) *connection {
	conn := getConnection(private)
	if conn == nil {
		conn = &connection{}
		conn.trans.init(&sp.transConfig, sp.watcher, sp.pub.onTransaction)
	}
	return conn
}

func (conn *connection) dropStreams() {
	conn.streams[0] = nil
	conn.streams[1] = nil
}

func getConnection(private protos.ProtocolData) *connection {
	if private == nil {
		return nil
	}

	priv, ok := private.(*connection)
	if !ok {
		logp.Warn("socks4 connection type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: socks4 connection data not set")
		return nil
	}
	return priv
}
