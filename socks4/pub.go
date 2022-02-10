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
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"

	"github.com/elastic/beats/v7/packetbeat/protos"
)

// Transaction Publisher.
type transPub struct {
	sendRequest  bool
	sendResponse bool

	results protos.Reporter
}

func (pub *transPub) onTransaction(requ, resp *message) error {
	if pub.results == nil {
		return nil
	}

	pub.results(pub.createEvent(requ, resp))
	return nil
}

func (pub *transPub) createEvent(requ, resp *message) beat.Event {
	status := common.OK_STATUS

	// resp_time in milliseconds
	responseTime := int32(resp.Ts.Sub(requ.Ts).Nanoseconds() / 1e6)

	src := &common.Endpoint{
		IP:      requ.Tuple.SrcIP.String(),
		Port:    requ.Tuple.SrcPort,
		Process: requ.CmdlineTuple.Src,
	}
	dst := &common.Endpoint{
		IP:      requ.Tuple.DstIP.String(),
		Port:    requ.Tuple.DstPort,
		Process: requ.CmdlineTuple.Dst,
	}

	socks4src := &common.MapStr{
		"IP":   src.IP,
		"Port": src.Port,
	}

	socks4dst := &common.MapStr{
		"IP":   requ.destination_ip,
		"Port": requ.destination_port,
	}

	command := ""
	switch requ.command {
	case 1:
		command = "CONNECT"
	case 2:
		command = "BIND"
	case 90:
		command = "REQUEST GRANTED"
	case 91:
		command = "REQUEST REJECTED (FAILED)"
	case 92:
		command = "REQUEST REJECTED (CONNECT ERROR)"
	case 93:
		command = "REQUEST REJECTED (USERID MISMATCH)"
	}

	socks4 := &common.MapStr{
		"version": requ.version,
		"command": command,
		"src":     socks4src,
		"dst":     socks4dst,
		"userid":  requ.userid,
	}

	fields := common.MapStr{
		"type":         "socks4",
		"status":       status,
		"responsetime": responseTime,
		"bytes_in":     requ.Size,
		"bytes_out":    resp.Size,
		"src":          src,
		"dst":          dst,
		"socks4":       socks4,
	}

	// add processing notes/errors to event
	if len(requ.Notes)+len(resp.Notes) > 0 {
		fields["notes"] = append(requ.Notes, resp.Notes...)
	}

	if pub.sendRequest {
		//fields["request"] =
	}
	if pub.sendResponse {
		// fields["response"] =
	}

	return beat.Event{
		Timestamp: requ.Ts,
		Fields:    fields,
	}
}
