// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package audit provides a NETLINK_AUDIT socket protocol.
package audit

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/netlink"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
)

// Protocol implements netlink.Protocol.
//
// +stateify savable
type Protocol struct{}

var _ netlink.Protocol = (*Protocol)(nil)

// NewProtocol creates a NETLINK_ROUTE netlink.Protocol.
func NewProtocol(t *kernel.Task) (netlink.Protocol, *syserr.Error) {
	log.Warningf("New Netlink created!\n")
	return &Protocol{}, nil
}

// Protocol implements netlink.Protocol.Protocol.
func (p *Protocol) Protocol() int {
	return linux.NETLINK_AUDIT
}

func AuditIterfaceFromContext(ctx context.Context) {
	k := kernel.KernelFromContext(ctx)
	k.netlinkPorts
}

// ProcessMessage implements netlink.Protocol.ProcessMessage.
func (p *Protocol) ProcessMessage(ctx context.Context, hdr linux.NetlinkMessageHeader, data []byte, ms *netlink.MessageSet) *syserr.Error {
	log.Warningf("Got some bytes for yah", string(data))
	msg := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: 1337,
	})
	msg.Put([]byte("Mason is a long string so likely I didnt get lucky"))
	msg.Put([]byte{0x0})
	log.Warningf("Sending mason")
	return nil
	//return syserr.ErrNotSupported
}

// init registers the NETLINK_ROUTE provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_AUDIT, NewProtocol)
}
