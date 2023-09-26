// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package pwru

import (
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Version is the pwru version and is set at compile time via LDFLAGS-
var Version string = "version unknown"

type FilterCfg struct {
	FilterNetns   uint32
	FilterMark    uint32
	FilterIfindex uint32

	// TODO: if there are more options later, then you can consider using a bit map
	OutputRelativeTS uint8
	OutputMeta       uint8
	OutputTuple      uint8
	OutputSkb        uint8
	OutputStack      uint8

	IsSet    byte
	TrackSkb byte
}

func GetConfig(flags *Flags) (cfg FilterCfg, err error) {
	cfg = FilterCfg{
		FilterMark: flags.FilterMark,
		IsSet:      1,
	}
	if flags.OutputSkb {
		cfg.OutputSkb = 1
	}
	if flags.OutputMeta {
		cfg.OutputMeta = 1
	}
	if flags.OutputTuple {
		cfg.OutputTuple = 1
	}
	if flags.OutputStack {
		cfg.OutputStack = 1
	}
	if flags.FilterTrackSkb {
		cfg.TrackSkb = 1
	}

	if cfg.FilterIfindex, cfg.FilterNetns, err = parseIfindexAndNetns(flags.FilterIfname, flags.FilterNetns); err != nil {
		return
	}
	fmt.Printf("FilterIfindex: %d, %d\n", cfg.FilterIfindex, cfg.FilterNetns)
	return
}

func parseIfindexAndNetns(ifname, netnsSpecifier string) (ifindex, netnsID uint32, err error) {
	var ns netns.NsHandle
	switch {
	case netnsSpecifier == "":
		ns, err = netns.Get()
	case strings.HasPrefix(netnsSpecifier, "/"):
		ns, err = netns.GetFromPath(netnsSpecifier)
	case strings.HasPrefix(netnsSpecifier, "inode:"):
		if ifname != "" {
			err = fmt.Errorf("inode netns specifier cannot be used with --filter-ifname")
		} else {
			netnsInode, err := strconv.Atoi(netnsSpecifier[6:])
			return 0, uint32(netnsInode), err
		}
	default:
		err = fmt.Errorf("invalid netns specifier: %s", netnsSpecifier)
	}
	if err != nil {
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	currentNetns, err := netns.Get()
	if err != nil {
		return
	}
	defer netns.Set(currentNetns)

	if err = netns.Set(ns); err != nil {
		return
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return
	}

	var s unix.Stat_t
	if err = unix.Fstat(int(ns), &s); err != nil {
		return
	}
	return uint32(iface.Index), uint32(s.Ino), nil
}
