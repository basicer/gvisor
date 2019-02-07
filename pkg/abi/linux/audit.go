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

package linux

/* The netlink messages for the audit system is divided into blocks:
 * 1000 - 1099 are for commanding the audit system
 * 1100 - 1199 user space trusted application messages
 * 1200 - 1299 messages internal to the audit daemon
 * 1300 - 1399 audit event messages
 * 1400 - 1499 SE Linux use
 * 1500 - 1599 kernel LSPP events
 * 1600 - 1699 kernel crypto events
 * 1700 - 1799 kernel anomaly records
 * 1800 - 1899 kernel integrity events
 * 1900 - 1999 future kernel use
 * 2000 is for otherwise unclassified kernel audit messages (legacy)
 * 2001 - 2099 unused (kernel)
 * 2100 - 2199 user space anomaly records
 * 2200 - 2299 user space actions taken in response to anomalies
 * 2300 - 2399 user space generated LSPP events
 * 2400 - 2499 user space crypto events
 * 2500 - 2999 future user space (maybe integrity labels and related events)
 *
 * Messages from 1000-1199 are bi-directional. 1200-1299 & 2100 - 2999 are
 * exclusively user space. 1300-2099 is kernel --> user space
 * communication.
 */

// Audit numbers identify different system call APIs, from <uapi/linux/audit.h>
const (
	// AUDIT_ARCH_X86_64 identifies AMD64.
	AUDIT_ARCH_X86_64 = 0xc000003e
	// AUDIT_ARCH_AARCH64 identifies ARM64.
	AUDIT_ARCH_AARCH64 = 0xc00000b7
)

const (
	AUDIT_GET         = 1000 /* Get status */
	AUDIT_SET         = 1001 /* Set status (enable/disable/auditd) */
	AUDIT_LIST        = 1002 /* List syscall rules -- deprecated */
	AUDIT_ADD         = 1003 /* Add syscall rule -- deprecated */
	AUDIT_DEL         = 1004 /* Delete syscall rule -- deprecated */
	AUDIT_USER        = 1005 /* Message from userspace -- deprecated */
	AUDIT_LOGIN       = 1006 /* Define the login id and information */
	AUDIT_WATCH_INS   = 1007 /* Insert file/dir watch entry */
	AUDIT_WATCH_REM   = 1008 /* Remove file/dir watch entry */
	AUDIT_WATCH_LIST  = 1009 /* List all file/dir watches */
	AUDIT_SIGNAL_INFO = 1010 /* Get info about sender of signal to auditd */
	AUDIT_ADD_RULE    = 1011 /* Add syscall filtering rule */
	AUDIT_DEL_RULE    = 1012 /* Delete syscall filtering rule */
	AUDIT_LIST_RULES  = 1013 /* List syscall filtering rules */
	AUDIT_TRIM        = 1014 /* Trim junk from watched tree */
	AUDIT_MAKE_EQUIV  = 1015 /* Append to watched tree */
	AUDIT_TTY_GET     = 1016 /* Get TTY auditing status */
	AUDIT_TTY_SET     = 1017 /* Set TTY auditing status */
	AUDIT_SET_FEATURE = 1018 /* Turn an audit feature on or off */
	AUDIT_GET_FEATURE = 1019 /* Get which features are enabled */
)
const (
	AUDIT_STATUS_ENABLED           = 0x0001
	AUDIT_STATUS_FAILURE           = 0x0002
	AUDIT_STATUS_PID               = 0x0004
	AUDIT_STATUS_RATE_LIMIT        = 0x0008
	AUDIT_STATUS_BACKLOG_LIMIT     = 0x0010
	AUDIT_STATUS_BACKLOG_WAIT_TIME = 0x0020
	AUDIT_STATUS_LOST              = 0x0040
)

const (
	AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT     = 0x00000001
	AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME = 0x00000002
	AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH   = 0x00000004
	AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND    = 0x00000008
	AUDIT_FEATURE_BITMAP_SESSIONID_FILTER  = 0x00000010
	AUDIT_FEATURE_BITMAP_LOST_RESET        = 0x00000020
	AUDIT_FEATURE_BITMAP_FILTER_FS         = 0x00000040
)

/* Failure-to-log actions */
const (
	AUDIT_FAIL_SILENT = 0
	AUDIT_FAIL_PRINTK = 1
	AUDIT_FAIL_PANIC  = 2
)

type AuditStatus struct {
	Mask              uint32 /* Bit mask for valid entries */
	Enabled           uint32 /* 1 = enabled, 0 = disabled */
	Failure           uint32 /* Failure-to-log action */
	Pid               uint32 /* pid of auditd process */
	Rate_limit        uint32 /* messages  rate limit (per second) */
	Backlog_limit     uint32 /* waiting messages limit */
	Lost              uint32 /* messages lost */
	Backlog           uint32 /* messages waiting in queue */
	Feature_bitmap    uint32 /* bitmap of kernel audit features */
	Backlog_wait_time uint32 /* message queue wait timeout */
}

type AuditFeatures struct {
	Vers     uint32
	Mask     uint32 /* which bits we are dealing with */
	Features uint32 /* which feature to enable/disable */
	Lock     uint32 /* which features to lock */
}
