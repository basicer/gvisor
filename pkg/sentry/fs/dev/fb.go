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
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/tmpfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/unimpl"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// +stateify savable
type fbDevice struct {
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

	backingFile *fs.File
}

func newFbDevice(ctx context.Context, owner fs.FileOwner, fp fs.FilePermissions) *fbDevice {

	k := kernel.KernelFromContext(ctx)
	if k == nil {
		panic("No kernel")
	}

	len := 800 * 600 * 32 / 8
	tmpfsInodeOps := tmpfs.NewInMemoryFile(ctx, usage.Tmpfs, fs.UnstableAttr{}, k)
	// This is not backed by a real filesystem, so we pass in nil.
	mnt := fs.NewNonCachingMountSource(nil, fs.MountSourceFlags{})
	tmpfsInode := fs.NewInode(tmpfsInodeOps, mnt, fs.StableAttr{})
	dirent := fs.NewDirent(tmpfsInode, "masn")
	tmpfsFile, err := tmpfsInode.GetFile(ctx, dirent, fs.FileFlags{Read: true, Write: true})
	dirent.DecRef()

	err = tmpfsInodeOps.Truncate(ctx, tmpfsInode, int64(len))
	if err != nil {
		panic(err)
	}

	return &fbDevice{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, fp, linux.TMPFS_MAGIC),
		backingFile:           tmpfsFile,
	}

}

// GetFile overrides ramfs.Entry.GetFile and returns a zeroFile instead.
func (fb *fbDevice) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	// Allow pread(2) and pwrite(2) on this file.
	flags.Pread = true
	flags.Pwrite = true

	f := fs.NewFile(ctx, dirent, flags, &fbFileOperations{
		backingFile: fb.backingFile,
	})

	log.Warningf("ioctl New File %s", f.UniqueID)

	return f, nil
}

// +stateify savable
type fbFileOperations struct {
	waiter.AlwaysReady       `state:"nosave"`
	fsutil.FileGenericSeek   `state:"nosave"`
	fsutil.FileNoopFlush     `state:"nosave"`
	fsutil.FileNoopFsync     `state:"nosave"`
	fsutil.FileNoopWrite     `state:"nosave"`
	fsutil.FileNoopRelease   `state:"nosave"`
	fsutil.FileNotDirReaddir `state:"nosave"`

	backingFile *fs.File
}

// Read implements fs.FileOperations.Read.
func (fb *fbFileOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	return fb.backingFile.FileOperations.Read(ctx, fb.backingFile, dst, offset)
}

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (fb *fbFileOperations) ConfigureMMap(ctx context.Context, file *fs.File, opts *memmap.MMapOpts) error {
	opts.Length = 800 * 600 * 32 / 8
	return fb.backingFile.FileOperations.ConfigureMMap(ctx, file, opts)
}

func (*fbFileOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	log.Warningf("/dev/fb0 ioctl %d", args[1].Uint)
	switch cmd := args[1].Uint(); cmd {
	case linux.FBIOGET_FSCREENINFO:
		var id [16]byte
		copy(id[:], "repl.it gfx")
		id[11] = 0
		data := fb_fix_screeninfo{
			id: id,
			//smem_start:  0,
			//smem_len:    0,
			//xpanstep:    22,
			//ypanstep:    44,
			//ywrapstep:   77,
			visual:      2, //FB_VISUAL_TRUECOLOR
			ftype:       0, //FB_TYPE_PACKED_PIXELS
			line_length: 800 * 4,
			//mmio_start:  1234,
		}
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), data, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case linux.FBIOGET_VSCREENINFO:
		data := fb_var_screeninfo{
			xres:           800,
			yres:           600,
			xres_virt:      800,
			yres_virt:      600,
			bits_per_pixel: 32,
			red:            fb_bitfield{offset: 0, length: 8, msb_right: 1},
			green:          fb_bitfield{offset: 8, length: 8, msb_right: 1},
			blue:           fb_bitfield{offset: 16, length: 8, msb_right: 1},
			transp:         fb_bitfield{offset: 24, length: 8, msb_right: 1},
		}
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), data, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	//case linux.FBIOPUT_VSCREENINFO:
	//	return 0, nil
	default:
		unimpl.EmitUnimplementedEvent(ctx)
		return 0, syserror.EINVAL
	}
}

type fb_var_screeninfo struct {
	xres           uint32
	yres           uint32
	xres_virt      uint32
	yres_virt      uint32
	xoffset        uint32
	yoffset        uint32
	bits_per_pixel uint32
	grayscale      uint32

	red    fb_bitfield
	green  fb_bitfield
	blue   fb_bitfield
	transp fb_bitfield

	nonstd   uint32
	activate uint32

	height uint32
	width  uint32
}

type fb_fix_screeninfo struct {
	id         [16]byte /* identification string eg "TT Builtin" */
	smem_start uint64   /* Start of frame buffer mem */
	/* (physical address) */
	smem_len    uint32 /* Length of frame buffer mem */
	ftype       uint32 /* see FB_TYPE_*		*/
	type_aux    uint32 /* Interleave for interleaved Planes */
	visual      uint32 /* see FB_VISUAL_*		*/
	xpanstep    uint16 /* zero if no hardware panning  */
	ypanstep    uint16 /* zero if no hardware panning  */
	ywrapstep   uint16 /* zero if no hardware ywrap    */
	spacer      uint16
	line_length uint32 /* length of a line in bytes    */
	mmio_start  uint64 /* Start of Memory Mapped I/O   */
	/* (physical address) */
	mmio_len uint32 /* Length of Memory Mapped I/O  */
	accel    uint32 /* Indicate to driver which	*/
	/*  specific chip/card we have	*/
	capabilities uint16    /* see FB_CAP_*			*/
	_reserved    [2]uint16 /* Reserved for future compatibility */
}

type fb_bitfield struct {
	offset    uint32
	length    uint32
	msb_right uint32
}
