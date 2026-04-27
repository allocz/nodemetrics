package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// SECTION_START error_helpers

func WrapN(err error, callerSkip int) error {
	if err == nil {
		return nil
	}
	pc, _, line, ok := runtime.Caller(callerSkip)
	if !ok {
		return fmt.Errorf("wrap: error calling runtime.Caller")
	}
	f := runtime.FuncForPC(pc)
	return fmt.Errorf("%s:%d: %w", f.Name(), line, err)
}

func Wrap(err error) error {
	return WrapN(err, 2)
}

func Wrap2(err error) error {
	return WrapN(err, 2)
}

func WrapMessage(mfmt string, args ...any) error {
	if mfmt == "" {
		return nil
	}
	pc, _, line, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("wrap: error calling runtime.Caller")
	}
	f := runtime.FuncForPC(pc)
	return fmt.Errorf(
		"%s:%d: %s", f.Name(), line, fmt.Errorf(mfmt, args...),
	)
}

func must(err error) {
	if err == nil {
		return
	}
	panic(err)
}

// SECTION_START cli_helpers

type cmdError struct {
	code int
	stderr bytes.Buffer
}

func (c *cmdError) Error() string {
	return fmt.Sprintf(
		"cmd error: exit code=%d stderr=%s",
		c.code,
		c.stderr.String(),
	)
}

func runCmd(cmd string) ([]byte, *cmdError) {
	var so bytes.Buffer
	var cerr cmdError
	c := exec.Command("bash", "-c", cmd)
	c.Stdout = &so
	c.Stderr = &cerr.stderr
	err := c.Run()
	if err != nil {
		cerr.code = err.(*exec.ExitError).ExitCode()
		return nil, &cerr
	}
	return so.Bytes(), nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// SECTION_START process_stats

const (
	statsLen = 52
)

const (
	// The process ID.
	s_pid = 1

	// The filename of the executable, in parentheses.
	// Strings longer than TASK_COMM_LEN (16) characters
	// (including the terminating null byte) are silently
	// truncated.  This is visible whether or not the
	// executable is swapped out.
	// 
	s_comm = 2

	// One of the following characters, indicating process
	// state:
	// 
	// R      Running
	// 
	// S      Sleeping in an interruptible wait
	// 
	// D      Waiting in uninterruptible disk sleep
	// 
	// Z      Zombie
	// 
	// T      Stopped (on a signal) or (before Linux
	//        2.6.33) trace stopped
	// 
	// t      Tracing stop (Linux 2.6.33 onward)
	// 
	// W      Paging (only before Linux 2.6.0)
	// 
	// X      Dead (from Linux 2.6.0 onward)
	// 
	// x      Dead (Linux 2.6.33 to 3.13 only)
	// 
	// K      Wakekill (Linux 2.6.33 to 3.13 only)
	// 
	// W      Waking (Linux 2.6.33 to 3.13 only)
	// 
	// P      Parked (Linux 3.9 to 3.13 only)
	// 
	// I      Idle (Linux 4.14 onward)
	// 
	s_state = 3

	// The PID of the parent of this process.
	// 
	s_ppid = 4

	// The process group ID of the process.
	// 
	s_pgrp = 5

	// The session ID of the process.
	// 
	s_session = 6

	// The controlling terminal of the process.  (The minor
	// device number is contained in the combination of
	// bits 31 to 20 and 7 to 0; the major device number is
	// in bits 15 to 8.)
	// 
	s_tty_nr = 7

	// The ID of the foreground process group of the
	// controlling terminal of the process.
	// 
	s_tpgid = 8

	// The kernel flags word of the process.  For bit
	// meanings, see the PF_* defines in the Linux kernel
	// source file include/linux/sched.h.  Details depend
	// on the kernel version.
	// 
	// The format for this field was %lu before Linux 2.6.
	// 
	s_flags = 9

	// The number of minor faults the process has made
	// which have not required loading a memory page from
	// disk.
	// 
	s_minflt = 10

	// The number of minor faults that the process's
	// waited-for children have made.
	// 
	s_cminflt = 11

	// The number of major faults the process has made
	// which have required loading a memory page from disk.
	// 
	s_majflt = 12

	// The number of major faults that the process's
	// waited-for children have made.
	// 
	s_cmajflt = 13

	// Amount of time that this process has been scheduled
	// in user mode, measured in clock ticks (divide by
	// sysconf(_SC_CLK_TCK)).  This includes guest time,
	// guest_time (time spent running a virtual CPU, see
	// below), so that applications that are not aware of
	// the guest time field do not lose that time from
	// their calculations.
	// 
	s_utime = 14

	// Amount of time that this process has been scheduled
	// in kernel mode, measured in clock ticks (divide by
	// sysconf(_SC_CLK_TCK)).
	// 
	s_stime = 15

	// Amount of time that this process's waited-for
	// children have been scheduled in user mode, measured
	// in clock ticks (divide by sysconf(_SC_CLK_TCK)).
	// (See also times(2).)  This includes guest time,
	// cguest_time (time spent running a virtual CPU, see
	// below).
	// 
	s_cutime = 16

	// Amount of time that this process's waited-for
	// children have been scheduled in kernel mode,
	// measured in clock ticks (divide by
	// sysconf(_SC_CLK_TCK)).
	// 
	s_cstime = 17

	// (Explanation for Linux 2.6) For processes running a
	// real-time scheduling policy (policy below; see
	// sched_setscheduler(2)), this is the negated
	// scheduling priority, minus one; that is, a number in
	// the range -2 to -100, corresponding to real-time
	// priorities 1 to 99.  For processes running under a
	// non-real-time scheduling policy, this is the raw
	// nice value (setpriority(2)) as represented in the
	// kernel.  The kernel stores nice values as numbers in
	// the range 0 (high) to 39 (low), corresponding to the
	// user-visible nice range of -20 to 19.
	// 
	// Before Linux 2.6, this was a scaled value based on
	// the scheduler weighting given to this process.
	// 
	s_priority = 18

	// The nice value (see setpriority(2)), a value in the
	// range 19 (low priority) to -20 (high priority).
	// 
	s_nice = 19

	// Number of threads in this process (since Linux 2.6).
	// Before Linux 2.6, this field was hard coded to 0 as
	// a placeholder for an earlier removed field.
	// 
	s_num_threads = 20

	// The time in jiffies before the next SIGALRM is sent
	// to the process due to an interval timer.  Since
	// Linux 2.6.17, this field is no longer maintained,
	// and is hard coded as 0.
	// 
	s_itrealvalue = 21

	// The time the process started after system boot.
	// Before Linux 2.6, this value was expressed in
	// jiffies.  Since Linux 2.6, the value is expressed in
	// clock ticks (divide by sysconf(_SC_CLK_TCK)).
	// 
	// The format for this field was %lu before Linux 2.6.
	// 
	s_starttime = 22

	// Virtual memory size in bytes.
	// 
	s_vsize = 23

	// Resident Set Size: number of pages the process has
	// in real memory.  This is just the pages which count
	// toward text, data, or stack space.  This does not
	// include pages which have not been demand-loaded in,
	// or which are swapped out.  This value is inaccurate;
	// see /proc/pid/statm below.
	// 
	s_rss = 24

	// Current soft limit in bytes on the rss of the
	// process; see the description of RLIMIT_RSS in
	// getrlimit(2).
	// 
	s_rsslim = 25

	// The address above which program text can run.
	// 
	s_startcode = 26

	// The address below which program text can run.
	// 
	s_endcode = 27

	// The address of the start (i.e., bottom) of the
	// stack.
	// 
	s_startstack = 28

	// The current value of ESP (stack pointer), as found
	// in the kernel stack page for the process.
	// 
	s_kstkesp = 29

	// The current EIP (instruction pointer).
	// 
	s_kstkeip = 30

	// The bitmap of pending signals, displayed as a
	// decimal number.  Obsolete, because it does not
	// provide information on real-time signals; use
	// /proc/pid/status instead.
	// 
	s_signal = 31

	// The bitmap of blocked signals, displayed as a
	// decimal number.  Obsolete, because it does not
	// provide information on real-time signals; use
	// /proc/pid/status instead.
	// 
	s_blocked = 32

	// The bitmap of ignored signals, displayed as a
	// decimal number.  Obsolete, because it does not
	// provide information on real-time signals; use
	// /proc/pid/status instead.
	// 
	s_sigignore = 33

	// The bitmap of caught signals, displayed as a decimal
	// number.  Obsolete, because it does not provide
	// information on real-time signals; use
	// /proc/pid/status instead.
	// 
	s_sigcatch = 34

	// This is the "channel" in which the process is
	// waiting.  It is the address of a location in the
	// kernel where the process is sleeping.  The
	// corresponding symbolic name can be found in
	// /proc/pid/wchan.
	// 
	s_wchan = 35

	// Number of pages swapped (not maintained).
	// 
	s_nswap = 36

	// Cumulative nswap for child processes (not
	// maintained).
	// 
	s_cnswap = 37

	// Signal to be sent to parent when we die.
	// 
	s_exit_signal = 38

	// CPU number last executed on.
	// 
	s_processor = 39

	// Real-time scheduling priority, a number in the range
	// 1 to 99 for processes scheduled under a real-time
	// policy, or 0, for non-real-time processes (see
	// sched_setscheduler(2)).
	// 
	s_rt_priority = 40

	// Scheduling policy (see sched_setscheduler(2)).
	// Decode using the SCHED_* constants in linux/sched.h.
	// 
	// The format for this field was %lu before Linux
	// 2.6.22.
	// 
	s_policy = 41

	// Aggregated block I/O delays, measured in clock ticks
	// (centiseconds).
	// 
	s_delayacct_blkio_ticks = 42

	// Guest time of the process (time spent running a
	// virtual CPU for a guest operating system), measured
	// in clock ticks (divide by sysconf(_SC_CLK_TCK)).
	// 
	s_guest_time = 43

	// Guest time of the process's children, measured in
	// clock ticks (divide by sysconf(_SC_CLK_TCK)).
	// 
	s_cguest_time = 44

	// Address above which program initialized and
	// uninitialized (BSS) data are placed.
	// 
	s_start_data = 45

	// Address below which program initialized and
	// uninitialized (BSS) data are placed.
	// 
	s_end_data = 46

	// Address above which program heap can be expanded
	// with brk(2).
	// 
	s_start_brk = 47

	// Address above which program command-line arguments
	// (argv) are placed.
	// 
	s_arg_start = 48

	// Address below program command-line arguments (argv)
	// are placed.
	// 
	s_arg_end = 49

	// Address above which program environment is placed.
	// 
	s_env_start = 50

	// Address below which program environment is placed.
	// 
	s_env_end = 51

	// The thread's exit status in the form reported by
	// waitpid(2).
	s_exit_code = 52
)

var sStrings = []string{
	"",
	"pid",
	"comm",
	"state",
	"ppid",
	"pgrp",
	"session",
	"tty_nr",
	"tpgid",
	"flags",
	"minflt",
	"cminflt",
	"majflt",
	"cmajflt",
	"utime",
	"stime",
	"cutime",
	"cstime",
	"priority",
	"nice",
	"num_threads",
	"itrealvalue",
	"starttime",
	"vsize",
	"rss",
	"rsslim",
	"startcode",
	"endcode",
	"startstack",
	"kstkesp",
	"kstkeip",
	"signal",
	"blocked",
	"sigignore",
	"sigcatch",
	"wchan",
	"nswap",
	"cnswap",
	"exit_signal",
	"processor",
	"rt_priority",
	"policy",
	"delayacct_blkio_ticks",
	"guest_time",
	"cguest_time",
	"start_data",
	"end_data",
	"start_brk",
	"arg_start",
	"arg_end",
	"env_start",
	"env_end",
	"exit_code",
}

func formatStat(stat [][]byte, items ...byte) string {
	var b bytes.Buffer
	if len(stat) != len(sStrings)-1 {
		panic("formatStat: unexpected stat length")
	}
	for _, v := range items {
		fmt.Fprintf(&b, "%s %s ", sStrings[v], stat[v-1])
	}
	return b.String()
}

func readStat(pid int) ([][]byte, error) {
	b, cerr := runCmd(fmt.Sprintf("cat /proc/%d/stat", pid))
	if cerr != nil {
		return nil, cerr
	}
	ba := bytes.Split(b, []byte(" "))
	if len(ba) != statsLen {
		return nil, fmt.Errorf("readStat: bad stat length")
	}
	return ba, nil
} 

type ioStat struct {
	rchar uint64
	wchar uint64
	syscr uint64
	syscw uint64
	read_bytes uint64
	write_bytes uint64
	cancelled_write_bytes uint64
}

func (i *ioStat) Update(pid int) error {
	const ioStatNRow = 7
	const ioStatNCol = 2
	var r ioStat
	expKeys := [][]byte{
		[]byte("rchar:"),
		[]byte("wchar:"),
		[]byte("syscr:"),
		[]byte("syscw:"),
		[]byte("read_bytes:"),
		[]byte("write_bytes:"),
		[]byte("cancelled_write_bytes:"),
	}
	o, cerr := runCmd(fmt.Sprintf("cat /proc/%d/io", pid))
	if cerr != nil {
		return Wrap(cerr)
	}
	ob := bytes.Split(o, []byte("\n"))
	if len(ob) > 1 {
		ob = ob[:len(ob)-1]
	}
	if len(ob) != ioStatNRow {
		return WrapMessage("unexpected row count")
	}
	for i, o := range ob {
		kv := bytes.Split(o, []byte(" "))
		if len(kv) != ioStatNCol {
			return WrapMessage("unexpected column count")
		}
		if !bytes.Equal(expKeys[i], kv[0]) {
			return WrapMessage("unexpected column key")
		}
		v, err := strconv.ParseUint(string(kv[1]), 10, 64)
		if err != nil {
			return Wrap(err)
		}
		switch i {
		case 0: r.rchar = v
		case 1: r.wchar = v
		case 2: r.syscr = v
		case 3: r.syscw = v
		case 4: r.read_bytes = v
		case 5: r.write_bytes = v
		case 6: r.cancelled_write_bytes = v
		}
	}
	*i = r
	return nil
}

func (i *ioStat) String() string {
	return fmt.Sprintf(
		"rchar %d wchar %d syscr %d syscw %d read_bytes %d" + 
		" write_bytes %d cacelled_write_bytes %d",
		i.rchar,
		i.wchar,
		i.syscr,
		i.syscw,
		i.read_bytes,
		i.write_bytes,
		i.cancelled_write_bytes,
	)
}

func pidRunning(pid int) bool {
	_, err := runCmd(fmt.Sprintf("kill -0 %d", pid))
	return err == nil
}

func signalSend(pid, signal int) bool {
	_, err := runCmd(fmt.Sprintf("kill %d %d", pid, signal))
	return err == nil
}

func clockTick() (uint64, error) {
	so, cerr := runCmd("getconf CLK_TCK")
	if cerr != nil {
		return 0, fmt.Errorf("clockTick: %w", cerr)
	}
	so = bytes.Trim(so, "\n")
	tick, err := strconv.ParseUint(string(so), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("clockTick: %w", cerr)
	}
	return tick, nil
}

func pSize() (uint64, error) {
	so, cerr := runCmd("getconf PAGE_SIZE")
	if cerr != nil {
		return 0, fmt.Errorf("pSize: %w", cerr)
	}
	so = bytes.Trim(so, "\n")
	v, err := strconv.ParseUint(string(so), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("pSize: %w", cerr)
	}
	return v, nil
}

// SECTION_START btcd

func btcdBuild(opts btcdOpts) error {
	const btcdRepoUrl = "https://github.com/allocz/btcd"
	const btcdRepoBranch = "checkpoint_no_prevout_disk_lookup"
	os.MkdirAll("data", 0o755)
	/*
	if !opts.ForceRebuild && binExists {
		return
	}
	build
	*/
	if !opts.forceRebuild && exists("data/btcd") {
		return nil
	}
	if !exists("data/btcd-src") {
		_, err := runCmd(
			fmt.Sprintf(`git clone %s data/btcd-src`, btcdRepoUrl),
		) 
		if err != nil {
			return Wrap(err)
		}
	}
	_, err := runCmd(
		`cd data/btcd-src && git branch | grep 'nodemetrics' \
		&& git checkout master && git branch -D nodemetrics \
		|| true`,
	)
	if err != nil {
		return Wrap(err)
	}
	cmd := `
cd data/btcd-src \
&& git fetch origin %s:nodemetrics \
&& git checkout nodemetrics \
&& CGO_ENABLED=0 go build -o ../btcd .
	`
	_, err = runCmd(fmt.Sprintf(cmd, btcdRepoBranch))
	if err != nil {
		return Wrap(err)
	}
	return nil
}

type btcdOpts struct {
	// args
	datadir string
	rpcuser string
	rpcpassword string
	profilePort int
	utxoCacheMB int
	mempoolMB int
	listenAddr string
	rpcListenAddr string
	checkpoint string
	nocheckpoint bool
	connect string
	pruneMB int

	// control
	stopHeight int
	statsLogFile string

	// args passed to the binary being executed
	binArgs []string

	description string

	// builder
	forceRebuild bool
}

func (o *btcdOpts) ParseFlags(args []string) error {
	fSet := flag.NewFlagSet("btcd", flag.ExitOnError)
	var binArgs []string
	defaultOpts := []struct{
		flagName string
		defaultV string
		binFlagName string
		flagDest any
	}{
		{"datadir", "./data/.btcd", "--datadir", &o.datadir},
		{"rpcuser", "bitcoin", "--rpcuser", &o.rpcuser},
		{"rpcpass", "bitcoin", "--rpcpass", &o.rpcpassword},
		{"profileport", "8080", "--profile", &o.profilePort},
		{"utxocache_mb", "300", "--utxocachemaxsize", &o.utxoCacheMB},
		{"mempool_mb", "10", "--blockprioritysize", &o.mempoolMB},
		{"listen_addr", "", "--listen", &o.listenAddr},
		{
			"rpc_listen_addr",
			"127.0.0.1:8332",
			"--rpclisten",
			&o.rpcListenAddr,
		},
		{
			"checkpoint",
			"946416:000000000000000000020a6dd2560429189a816e21d54c9221f4a3a029d322a7",
			"--addcheckpoint",
			&o.checkpoint,
		},
		{"nocheckpoint", "", "--nocheckpoints", &o.nocheckpoint},
		{"connect", "", "--connect", &o.connect},
		{"prune_mb", "", "--prune", &o.pruneMB},
		// internal
		{"stop_height", "", "", &o.stopHeight},
		{"stats_logfile", "", "", &o.statsLogFile},
		{"description", "", "", &o.description},
		{"force_rebuild", "", "", &o.forceRebuild},
	}
	for _, opt := range defaultOpts {
		switch dest := opt.flagDest.(type) {
		case *string:
			fSet.StringVar(dest, opt.flagName, opt.defaultV, "")
		case *bool:
			v := opt.defaultV != ""
			fSet.BoolVar(dest, opt.flagName, v, "")
		case *int:
			var v int
			var err error
			if opt.defaultV != "" {
				v, err = strconv.Atoi(opt.defaultV)
				if err != nil {
					return Wrap(err)
				}
			}
			fSet.IntVar(dest, opt.flagName, v, "")
		default:
			return fmt.Errorf("unkown flag type %T", opt.flagDest)
		}
	}
	err := fSet.Parse(args)
	if err != nil {
		return Wrap(err)
	}
	if o.nocheckpoint {
		o.checkpoint = ""
	}
	for _, opt := range defaultOpts {
		if opt.binFlagName == "" {
			continue
		}
		switch dest := opt.flagDest.(type) {
		case *string:
			if *dest == "" {
				continue
			}
			binArgs = append(
				binArgs,
				fmt.Sprintf("%s=%s", opt.binFlagName, *dest),
			)
		case *bool:
			if *dest == false {
				continue
			}
			binArgs = append(
				binArgs,
				fmt.Sprintf("%s", opt.binFlagName),
			)
		case *int:
			if *dest == 0 {
				continue
			}
			binArgs = append(
				binArgs,
				fmt.Sprintf("%s=%d", opt.binFlagName, *dest),
			)
		default:
			return fmt.Errorf("unkown flag type %T", opt.flagDest)
		}
	}
	o.binArgs = binArgs
	return nil
}

func btcdFetchBlockCount(nodeRpcUrl, rpcUser, rpcPassword string) (int, error) {
	var c http.Client
	c.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	var reqBody bytes.Buffer
	reqBody.WriteString(
		`{"method":"getblockcount","params":[],"id":0,"jsonrpc":"2.0"}`,
	)
	req, err := http.NewRequest("POST", nodeRpcUrl, &reqBody)
	if err != nil {
		return 0, Wrap(err)
	}
	req.SetBasicAuth(rpcUser, rpcPassword)
	res, err := c.Do(req)
	if err != nil {
		return 0, Wrap(err)
	}
	defer res.Body.Close()
	if s := res.StatusCode; s != 200 {
		return 0, WrapMessage("unexpected status code %d", s)
	}
	var resultData struct {
		Result int `json:"result"`
	}
	var resBody bytes.Buffer
	_, err = resBody.ReadFrom(res.Body)
	if err != nil {
		return 0, Wrap(err)
	}
	err = json.Unmarshal(resBody.Bytes(), &resultData)
	if err != nil {
		return 0, WrapMessage(
			"request body: %s, err: %w", resBody.Bytes(), err,
		)
	}
	return resultData.Result, nil
}

type btcdStats struct {
	// timing
	StartTs int64
	LastTs int64

	// memory and CPU stats
	VMmaxBytes uint64
	VMbytes uint64
	RSSmaxBytes uint64
	RSSbytes uint64
	CPUuserNS uint64
	CPUsystemNS uint64

	// I/O stats
	StorageReadBytes uint64
	StorageWriteBytes uint64
	RcharBytes uint64
	WcharBytes uint64

	// storage usage
	DataStoreSizeBytes uint64

	// height tracking
	startHeightSet bool
	StartHeight int
	CurrentHeight int

	NsPerBlock uint64
	Obs string
}

func newBtcdStats(obs string) *btcdStats {
	return &btcdStats{
		StartTs: time.Now().Unix(),
		Obs: obs,
	}
}

func (s *btcdStats) update(
	pid int, nodeRpcUrl, nodeRpcUser, nodeRpcPassword, dataDir string,
) error {
	statUint64 := func(pid int, indexes ...int) ([]uint64, error) {
		stats, err := readStat(pid)
		if err != nil {
			return nil, Wrap(err)
		}
		r := make([]uint64, 0, len(indexes))
		for _, i := range indexes {
			tmp, err := strconv.ParseUint(string(stats[i]), 10, 64)
			if err != nil {
				return nil, Wrap(err)
			}
			r = append(r, tmp)
		}
		return r, nil
	}
	dirSizeBytes := func(dir string) (uint64, error) {
		out, cerr := runCmd(fmt.Sprintf("du -d 0 %s", dir))
		if cerr != nil {
			return 0, Wrap(cerr)
		}
		values := bytes.Split(out, []byte("\t"))
		size, err := strconv.ParseUint(string(values[0]), 10, 64)
		if err != nil {
			return 0, Wrap(err)
		}
		return size, nil
	}

	s.LastTs = time.Now().Unix()

	pageSize, err := pSize()
	if err != nil {
		return Wrap(err)
	}
	var clockTickMul uint64
	{
		clockTicks, err := clockTick()
		if err != nil {
			return Wrap(err)
		}
		clockTickMul = 1_000_000_000/clockTicks
	}

	// memory and CPU stats
	procStat, err := statUint64(
		pid, s_vsize-1, s_rss-1, s_utime-1, s_stime-1,
	)
	if err != nil {
		return Wrap(err)
	}
	s.VMbytes = procStat[0]
	s.VMmaxBytes = max(s.VMmaxBytes, s.VMbytes)
	s.RSSbytes = procStat[1]*pageSize
	s.RSSmaxBytes = max(s.RSSmaxBytes, s.RSSbytes)
	s.CPUuserNS = procStat[2]*clockTickMul
	s.CPUsystemNS = procStat[3]*clockTickMul

	// I/O stats
	var ios ioStat
	err = ios.Update(pid)
	if err != nil {
		return Wrap(err)
	}
	s.StorageReadBytes = ios.read_bytes
	s.StorageWriteBytes = ios.write_bytes
	s.RcharBytes = ios.rchar
	s.WcharBytes = ios.wchar

	dataDirSize, err := dirSizeBytes(dataDir)
	if err != nil {
		log.Println(WrapMessage("failed to get data size: %w", err))
	} else {
		s.DataStoreSizeBytes = dataDirSize
	}

	// height tracking
	h, err := btcdFetchBlockCount(nodeRpcUrl, nodeRpcUser, nodeRpcPassword)
	if err != nil {
		log.Println(
			WrapMessage("failure to fetch block count: %w", err),
		)
	} else {
		if !s.startHeightSet {
			s.StartHeight = h
			s.startHeightSet = true
		}
		s.CurrentHeight = h
		heightDelta := int64(s.CurrentHeight - s.StartHeight)
		if heightDelta > 0 {
			s.NsPerBlock = uint64(
				((s.LastTs-s.StartTs) * 1_000_000_000) /
				heightDelta,
			)
		}
	}

	return nil
}

func btcdMonitor(pid int, opts btcdOpts) error {
	checkInterval := time.Second * 1
	stats := newBtcdStats(
		fmt.Sprintf(
			"implementation=%s" +
			" mempool_mb=%d" +
			" utxocache_mb=%d" +
			" assumevalid=%s" +
			" noassumevalid=%t" +
			" obs=%s",
			"bitcoind",
			opts.mempoolMB,
			opts.utxoCacheMB,
			opts.checkpoint,
			opts.nocheckpoint,
			opts.description,
		),
	)
	for pidRunning(pid) {
		err := stats.update(
			pid,
			"https://"+opts.rpcListenAddr,
			opts.rpcuser,
			opts.rpcpassword,
			opts.datadir,
		)
		if err != nil {
			log.Println(Wrap(err))
		}
		if opts.stopHeight > 0 &&
		stats.CurrentHeight >= opts.stopHeight {

			signalSend(pid, int(syscall.SIGTERM))
		}
		time.Sleep(checkInterval)
	}
	var statsLog io.Writer = os.Stderr
	if l := opts.statsLogFile; l != "" {
		lf, err := os.OpenFile(l, os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			log.Println(Wrap(err))
			goto skip
		}
		defer lf.Close()
		_, err = lf.Seek(0, io.SeekEnd)
		if err != nil {
			log.Println(Wrap(err))
			goto skip
		}
		statsLog = lf
	}
skip:
	r, err := json.MarshalIndent(stats, "", "	")
	if err != nil {
		return Wrap(err)
	}
	r = append(r, []byte("\n")...)
	_, err = statsLog.Write(r)
	if err != nil {
		return Wrap(err)
	}
	return nil
}

func btcdRun(ctx context.Context, opts btcdOpts) error {
	err := btcdBuild(opts)
	if err != nil {
		return Wrap(err)
	}

	execCmd := "./data/btcd"
	log.Println("starting btcd with args: ", opts.binArgs)

	cmd := exec.Command(execCmd, opts.binArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		return Wrap(err)
	}
	btcdDone := make(chan struct{})
	go func() {
		cmd.Wait()
		close(btcdDone)
	}()

	btcdMonitorDone := make(chan struct{})
	go func() {
		err = btcdMonitor(cmd.Process.Pid, opts)
		if err != nil {
			log.Println(Wrap(err))
		}
		close(btcdMonitorDone)
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Signal(syscall.SIGTERM)
	case <-btcdDone:
	}
	<-btcdDone
	<-btcdMonitorDone
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		return WrapMessage("btcd exited with code %d", code)
	}
	return nil
}

func btcdCommand(ctx context.Context, args []string) error {
	var opts btcdOpts
	err := opts.ParseFlags(args[:])
	if err != nil {
		return Wrap(err)
	}
	err = btcdRun(
		ctx,
		opts,
	)
	if err != nil {
		return Wrap(err)
	}
	return nil
}

// SECTION_BITCOIND

func bitcoindDownload(_ bitcoindOpts) error {
	const bitcoindBinURL = "https://bitcoincore.org/bin/bitcoin-core-31.0/bitcoin-31.0-x86_64-linux-gnu.tar.gz"
	const bitcoindHash = "d3e4c58a35b1d0a97a457462c94f55501ad167c660c245cb1ffa565641c65074"
	os.MkdirAll("data", 0o755)
	if !exists("data/bitcoind/bin/bitcoind") {
		cmd := `
set -e
cd data
curl -Lo bitcoind.tar.gz %s
sha256sum bitcoind.tar.gz | grep '%s'
tar -xf bitcoind.tar.gz
rm bitcoind.tar.gz
mv bitcoin-* bitcoind
		`
		_, err := runCmd(fmt.Sprintf(cmd, bitcoindBinURL, bitcoindHash))
		if err != nil {
			return Wrap(err)
		}
		return nil
	}
	return nil
}

type bitcoindOpts struct {
	// args
	datadir string
	rpcuser string
	rpcpassword string
	utxoCacheMB int
	mempoolMB int
	listenAddr string
	rpcListenAddr string
	checkpoint string
	nocheckpoint bool
	connect string
	pruneMB int

	// control
	stopHeight int
	statsLogFile string

	// args passed to the binary being executed
	binArgs []string

	description string
}

func (o *bitcoindOpts) ParseFlags(args []string) error {
	fSet := flag.NewFlagSet("btcd", flag.ExitOnError)
	var binArgs []string
	type optItem struct {
		flagName string
		defaultV string
		binFlagName string
		flagDest any
	}
	defaultOpts := []optItem {
		{"datadir", "./data/.bitcoind", "--datadir", &o.datadir},
		{"rpcuser", "bitcoin", "--rpcuser", &o.rpcuser},
		{"rpcpass", "bitcoin", "--rpcpassword", &o.rpcpassword},
		{"utxocache_mb", "300", "--dbcache", &o.utxoCacheMB},
		{"mempool_mb", "10", "--maxmempool", &o.mempoolMB},
		{"listen_addr", "", "--listen", &o.listenAddr},
		{
			"rpc_listen_addr",
			"127.0.0.1:8332",
			"--rpcbind",
			&o.rpcListenAddr,
		},
		{
			"checkpoint",
			"000000000000000000020a6dd2560429189a816e21d54c9221f4a3a029d322a7",
			"--assumevalid",
			&o.checkpoint,
		},
		{"nocheckpoint", "", "", &o.nocheckpoint},
		{"connect", "", "--connect", &o.connect},
		{"prune_mb", "", "--prune", &o.pruneMB},
		// internal
		{"stop_height", "", "", &o.stopHeight},
		{"stats_logfile", "", "", &o.statsLogFile},
		{"description", "", "", &o.description},
	}
	for _, opt := range defaultOpts {
		switch dest := opt.flagDest.(type) {
		case *string:
			fSet.StringVar(dest, opt.flagName, opt.defaultV, "")
		case *bool:
			v := opt.defaultV != ""
			fSet.BoolVar(dest, opt.flagName, v, "")
		case *int:
			var v int
			var err error
			if opt.defaultV != "" {
				v, err = strconv.Atoi(opt.defaultV)
				if err != nil {
					return Wrap(err)
				}
			}
			fSet.IntVar(dest, opt.flagName, v, "")
		default:
			return fmt.Errorf("unkown flag type %T", opt.flagDest)
		}
	}
	err := fSet.Parse(args)
	if err != nil {
		return Wrap(err)
	}
	if o.nocheckpoint {
		o.checkpoint = "0"
	}
	if o.rpcListenAddr != "" {
		var dst string
		defaultOpts = append(defaultOpts, optItem{
			flagName:    "",
			defaultV:    "0.0.0.0/0",
			binFlagName: "--rpcallowip",
			flagDest:    &dst,
		})
	}
	for _, opt := range defaultOpts {
		if opt.binFlagName == "" {
			continue
		}
		switch dest := opt.flagDest.(type) {
		case *string:
			if *dest == "" {
				continue
			}
			binArgs = append(
				binArgs,
				fmt.Sprintf("%s=%s", opt.binFlagName, *dest),
			)
		case *bool:
			if *dest == false {
				continue
			}
			binArgs = append(
				binArgs,
				fmt.Sprintf("%s", opt.binFlagName),
			)
		case *int:
			if *dest == 0 {
				continue
			}
			binArgs = append(
				binArgs,
				fmt.Sprintf("%s=%d", opt.binFlagName, *dest),
			)
		default:
			return fmt.Errorf("unkown flag type %T", opt.flagDest)
		}
	}
	o.binArgs = binArgs
	return nil
}

func bitcoindMonitor(pid int, opts bitcoindOpts) error {
	checkInterval := time.Second * 1
	stats := newBtcdStats(
		fmt.Sprintf(
			"implementation=%s" +
			" mempool_mb=%d" +
			" utxocache_mb=%d" +
			" assumevalid=%s" +
			" noassumevalid=%t" +
			" obs=%s",
			"btcd",
			opts.mempoolMB,
			opts.utxoCacheMB,
			opts.checkpoint,
			opts.nocheckpoint,
			opts.description,
		),
	)
	for pidRunning(pid) {
		err := stats.update(
			pid,
			"http://"+opts.rpcListenAddr,
			opts.rpcuser,
			opts.rpcpassword,
			opts.datadir,
		)
		if err != nil {
			log.Println(Wrap(err))
		}
		if opts.stopHeight > 0 &&
		stats.CurrentHeight >= opts.stopHeight {

			signalSend(pid, int(syscall.SIGTERM))
		}
		time.Sleep(checkInterval)
	}
	var statsLog io.Writer = os.Stderr
	if l := opts.statsLogFile; l != "" {
		lf, err := os.OpenFile(l, os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			log.Println(Wrap(err))
			goto skip
		}
		defer lf.Close()
		_, err = lf.Seek(0, io.SeekEnd)
		if err != nil {
			log.Println(Wrap(err))
			goto skip
		}
		statsLog = lf
	}
skip:
	r, err := json.MarshalIndent(stats, "", "	")
	if err != nil {
		return Wrap(err)
	}
	r = append(r, []byte("\n")...)
	_, err = statsLog.Write(r)
	if err != nil {
		return Wrap(err)
	}
	return nil
}

func bitcoindRun(ctx context.Context, opts bitcoindOpts) error {
	bitcoindDownload(opts)

	execCmd := "./data/bitcoind/bin/bitcoind"
	log.Println("starting bitcoind with args: ", opts.binArgs)
	os.MkdirAll(opts.datadir, 0o755)

	cmd := exec.Command(execCmd, opts.binArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		return Wrap(err)
	}
	bitcoindDone := make(chan struct{})
	go func() {
		cmd.Wait()
		close(bitcoindDone)
	}()

	bitcoindMonitorDone := make(chan struct{})
	go func() {
		err = bitcoindMonitor(cmd.Process.Pid, opts)
		if err != nil {
			log.Println(Wrap(err))
		}
		close(bitcoindMonitorDone)
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Signal(syscall.SIGTERM)
	case <-bitcoindDone:
	}
	<-bitcoindDone
	<-bitcoindMonitorDone
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		return WrapMessage("btcd exited with code %d", code)
	}
	return nil
}

func bitcoindCommand(ctx context.Context, args []string) error {
	var opts bitcoindOpts
	err := opts.ParseFlags(args[:])
	if err != nil {
		return Wrap(err)
	}
	err = bitcoindRun(
		ctx,
		opts,
	)
	if err != nil {
		return Wrap(err)
	}
	return nil
}


// SECTION_START main

func run() error {
	ctx, cancel := signal.NotifyContext(
		context.Background(), syscall.SIGTERM, syscall.SIGINT,
	)
	defer cancel()
	printHelpMessage := func() {
		fmt.Fprintln(os.Stderr, "usage: < btcd | bitcoind >")
	}
	if len(os.Args) < 2 {
		printHelpMessage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "btcd":
		return btcdCommand(ctx, os.Args[2:])
	case "bitcoind":
		return bitcoindCommand(ctx, os.Args[2:])
	case "-h","--help","help":
		printHelpMessage()
		return nil
	default: 
		printHelpMessage()
		os.Exit(1)
	}
	return nil
}

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}
