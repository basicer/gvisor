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

var chosenOne *netlink.Socket
var chosenTask *kernel.Task

const (
	AUDIT_STATUS_ENABLED           = 0x0001
	AUDIT_STATUS_FAILURE           = 0x0002
	AUDIT_STATUS_PID               = 0x0004
	AUDIT_STATUS_RATE_LIMIT        = 0x0008
	AUDIT_STATUS_BACKLOG_LIMIT     = 0x0010
	AUDIT_STATUS_BACKLOG_WAIT_TIME = 0x0020
	AUDIT_STATUS_LOST              = 0x0040
)

type audit_status struct {
	mask              uint32 /* Bit mask for valid entries */
	enabled           uint32 /* 1 = enabled, 0 = disabled */
	failure           uint32 /* Failure-to-log action */
	pid               uint32 /* pid of auditd process */
	rate_limit        uint32 /* messages  rate limit (per second) */
	backlog_limit     uint32 /* waiting messages limit */
	lost              uint32 /* messages lost */
	backlog           uint32 /* messages waiting in queue */
	feature_bitmap    uint32 /* bitmap of kernel audit features */
	backlog_wait_time uint32 /* message queue wait timeout */
}

type audit_features struct {
	vers     uint32
	mask     uint32 /* which bits we are dealing with */
	features uint32 /* which feature to enable/disable */
	lock     uint32 /* which features to lock */
}

// ProcessMessage implements netlink.Protocol.ProcessMessage.
func (p *Protocol) ProcessMessage(ctx context.Context, hdr linux.NetlinkMessageHeader, data []byte, ms *netlink.MessageSet, s *netlink.Socket) *syserr.Error {
	log.Warningf("Got some bytes for yah %d, %s", hdr.Type, string(data))
	switch hdr.Type {
	case 1000: //AUDIT_GET
		status := audit_status{
			mask:    AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID,
			enabled: 0,
			pid:     0,
		}
		if chosenOne != nil {
			status.enabled = 1
		}
		if chosenTask != nil {
			status.pid = uint32(chosenTask.ThreadGroup().ID())
		}
		ms.AddMessage(linux.NetlinkMessageHeader{
			Type: 1000,
		}).Put(status)
		return nil
	case 1001: //AUDIT_SET
		chosenOne = s
		chosenTask = kernel.TaskFromContext(ctx)
		return nil
	case 1005: //linux.AUDIT_USER:
		if chosenOne != nil {
			msg := &netlink.MessageSet{}
			msg.AddMessage(hdr).Put(data)
			chosenOne.Publish(ctx, msg)
		}
		return nil
	case 1019: //AUDIT_GET_FEATURE
		ms.AddMessage(linux.NetlinkMessageHeader{
			Type: 1019,
		}).Put(audit_features{
			vers:     1,
			mask:     0xFFFF,
			features: 0,
			lock:     0,
		})
		return nil

	default:
		msg := ms.AddMessage(linux.NetlinkMessageHeader{
			Type: 1337,
		})
		msg.Put([]byte("Mason is a long string so likely I didnt get lucky"))
		msg.Put([]byte{0x0})
		log.Warningf("Sending mason")
		return nil
	}

	return syserr.ErrNotSupported
}

// init registers the NETLINK_ROUTE provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_AUDIT, NewProtocol)
}
