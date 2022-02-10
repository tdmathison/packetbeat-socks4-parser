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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/elastic/beats/v7/libbeat/common/streambuf"
	"github.com/elastic/beats/v7/packetbeat/protos/applayer"
)

type parser struct {
	buf     streambuf.Buffer
	config  *parserConfig
	message *message

	onMessage func(m *message) error
}

type parserConfig struct {
	maxBytes int
}

type message struct {
	applayer.Message

	version          int
	command          int
	destination_port int64
	destination_ip   string
	userid           string
	partialparse     bool

	// indicator for parsed message being complete or requires more messages
	// (if false) to be merged to generate full message.
	isComplete bool

	// list element use by 'transactions' for correlation
	next *message
}

// Error code if stream exceeds max allowed size on append.
var (
	ErrStreamTooLarge = errors.New("stream data too large")
)

func (p *parser) init(
	cfg *parserConfig,
	onMessage func(*message) error,
) {
	*p = parser{
		buf:       streambuf.Buffer{},
		config:    cfg,
		onMessage: onMessage,
	}
}

func (p *parser) append(data []byte) error {
	_, err := p.buf.Write(data)
	if err != nil {
		return err
	}

	if p.config.maxBytes > 0 && p.buf.Total() > p.config.maxBytes {
		return ErrStreamTooLarge
	}
	return nil
}

func (p *parser) feed(ts time.Time, data []byte) error {
	if err := p.append(data); err != nil {
		return err
	}

	for p.buf.Total() > 0 {
		if p.message == nil {
			// allocate new message object to be used by parser with current timestamp
			p.message = p.newMessage(ts)
		}

		msg, err := p.parse()
		if err != nil {
			return err
		}
		if msg == nil {
			break // wait for more data
		}

		// reset buffer and message -> handle next message in buffer
		p.buf.Advance(p.buf.Total())
		p.buf.Reset()
		p.message = nil

		// call message handler callback
		if err := p.onMessage(msg); err != nil {
			return err
		}
	}

	return nil
}

func (p *parser) newMessage(ts time.Time) *message {
	return &message{
		Message: applayer.Message{
			Ts: ts,
		},
	}
}

func (p *parser) parse() (*message, error) {
	// looking to parse connect and bind operations
	/* CONNECT
	+----+----+----+----+----+----+----+----+----+----+....+----+
	| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
	+----+----+----+----+----+----+----+----+----+----+....+----+
		1    1      2              4           variable       1

	VN is the SOCKS protocol version number and should be 4. CD is the
	SOCKS command code and should be 1 for CONNECT request. NULL is a byte
	of all zero bits
	*/

	/* REPLY packet
	+----+----+----+----+----+----+----+----+
	| VN | CD | DSTPORT |      DSTIP        |
	+----+----+---------+----+----+----+----+
		1    1      2              4

	VN is the version of the reply code and should be 0. CD is the result
	code with one of the following values:

		90: request granted
		91: request rejected or failed
		92: request rejected becasue SOCKS server cannot connect to
			identd on the client
		93: request rejected because the client program and identd
			report different user-ids
	*/

	/* BIND
	+----+----+----+----+----+----+----+----+----+----+....+----+
	| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
	+----+----+----+----+----+----+----+----+----+----+....+----+
	1    1      2              4           variable       1

	VN is again 4 for the SOCKS protocol version number. CD must be 2 to
	indicate BIND request
	*/

	/* REPLY packet
	+----+----+----+----+----+----+----+----+
	| VN | CD | DSTPORT |      DSTIP        |
	+----+----+----+----+----+----+----+----+
		1    1      2              4

	VN is the version of the reply code and should be 0. CD is the result
	code with one of the following values:

		90: request granted
		91: request rejected or failed
		92: request rejected becasue SOCKS server cannot connect to
			identd on the client
		93: request rejected because the client program and identd
			report different user-ids
	*/

	/*buf, err := p.buf.CollectUntil([]byte{'\n'})
	if err == streambuf.ErrNoMoreBytes {
		return nil, nil
	}
	debugf("%x", buf)
	return nil, nil*/

	//p.message.Size = uint64(p.buf.BufferConsumed())

	err := p.parse_packet()

	if err == nil {
		debugf("socks4.version: %d, socks4.command: %d, socks4.destination_port: %d, socks4.destination_ip: %s, socks4.userid: %s",
			p.message.version, p.message.command, p.message.destination_port, p.message.destination_ip, p.message.userid)

		return p.message, nil
	}

	if p.message.partialparse {
		debugf("parse() waiting for more bytes...")
		return nil, nil
	}

	return nil, errors.New("not interested in packet")
}

func (p *parser) parse_packet() error {
	p.message.partialparse = false
	buffer := p.buf.BufferedBytes()

	// Get socks version number and command id
	if len(buffer) >= 2 {
		if buffer[0] == '\x04' /*socks version*/ {
			p.message.version = 4

			if buffer[1] == '\x01' /* CONNECT */ || buffer[1] == '\x02' /* BIND */ {
				p.message.Direction = applayer.NetOriginalDirection
				p.message.IsRequest = true
			}
		} else if buffer[0] == '\x00' /*reply code version*/ {
			p.message.version = 0

			if buffer[1] == '\x5a' || // 90: request granted
				buffer[1] == '\x5b' || // 91: request rejected or failed
				buffer[1] == '\x5c' || // 92: request rejected becasue SOCKS server cannot connect to identd on the client
				buffer[1] == '\x5d' { // 93: request rejected because the client program and identd report different user-ids
				p.message.Direction = applayer.NetReverseDirection
				p.message.IsRequest = false
			}
		} else {
			return errors.New("failed to parse socks4connect struct")
		}

		p.message.command = int(buffer[1])
		p.message.partialparse = true

		// Get destination port
		if len(buffer) >= 4 {
			port_number, _ := strconv.ParseInt(hex.EncodeToString(buffer[2:4]), 16, 32)
			p.message.destination_port = port_number

			if len(buffer) >= 8 {
				// Get IP address
				ip_address, _ := hex.DecodeString(hex.EncodeToString(buffer[4:8]))
				p.message.destination_ip = fmt.Sprintf("%v.%v.%v.%v",
					ip_address[0],
					ip_address[1],
					ip_address[2],
					ip_address[3])

				if p.message.Direction == applayer.NetOriginalDirection {
					if len(buffer) >= 9 {
						index := bytes.Index(buffer[8:], []byte{00})
						if index != -1 {
							p.message.userid = string(buffer[8 : 8+index])
						} else {
							p.message.userid = ""
						}

						p.message.Size = uint64(9 + len(p.message.userid))
						return nil
					}
				} else {
					p.message.Size = 9
					return nil
				}
			}
		}
	}

	return errors.New("failed to parse socks4connect struct")
}
