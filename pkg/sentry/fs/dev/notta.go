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

package dev

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// +stateify savable
type nottaDevice struct {
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNoopTruncate         `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.InodeVirtual              `state:"nosave"`

	fsutil.InodeSimpleAttributes
}

func newNottaDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *nottaDevice {
	return &nottaDevice{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, fs.FilePermsFromMode(mode), linux.TMPFS_MAGIC),
	}
}

// GetFile overrides ramfs.Entry.GetFile and returns a nottaFile instead.
func (n *nottaDevice) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	// Allow pread(2) and pwrite(2) on this file.
	flags.Pread = true
	flags.Pwrite = true

	return fs.NewFile(ctx, dirent, flags, &nottaFileOperations{
		termios: linux.DefaultSlaveTermios,
	}), nil
}

// +stateify savable
type nottaFileOperations struct {
	waiter.AlwaysReady       `state:"nosave"`
	fsutil.FileGenericSeek   `state:"nosave"`
	fsutil.FileNoMMap        `state:"nosave"`
	fsutil.FileNoopFlush     `state:"nosave"`
	fsutil.FileNoopFsync     `state:"nosave"`
	fsutil.FileNoopWrite     `state:"nosave"`
	fsutil.FileNoopRelease   `state:"nosave"`
	fsutil.FileNotDirReaddir `state:"nosave"`

	readNothing `state:"nosave"`
	termios     linux.KernelTermios
}

func (n *nottaFileOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch args[1].Uint() {
	case 0x4B33: // linux.KDGKBTYPE
		val := []byte{0x02}
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), val, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case 0x00005600: //  VT_OPENQRY
		val := []uint32{0}
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), val, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case linux.TCGETS:
		t := n.termios.ToTermios()
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), t, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case linux.TCSETS:
		fallthrough
	case linux.TCSETSW:
		var t linux.Termios
		_, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &t, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		n.termios.FromTermios(t)
		return 0, err
	default:
		return 0, nil
	}
}
