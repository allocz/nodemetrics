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
	"strings"
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

func pageSize() (uint64, error) {
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

// SECTION_START process_stats

func procPidStatGen() string {
	const (
		typeU64 = "uint64"
		typeStr = "string"
	)
	genTable := []struct{
		name string
		ftype string
	}{
		// reference: https://www.man7.org/linux/man-pages//man5/proc_pid_stat.5.html
		{"Pid", typeU64},
		{"Comm", typeStr},
		{"State", typeStr},
		{"Ppid", typeU64},
		{"Pgrp", typeU64},
		{"Session", typeU64},
		{"TtyNr", typeU64},
		{"Tpgid", typeU64},
		{"Flags", typeU64},
		{"Minflt", typeU64},
		{"Cminflt", typeU64},
		{"Majflt", typeU64},
		{"Cmajflt", typeU64},
		{"Utime", typeU64},
		{"Stime", typeU64},
		{"Cutime", typeU64},
		{"Cstime", typeU64},
		{"Priority", typeU64},
		{"Nice", typeU64},
		{"NumThreads", typeU64},
		{"Itrealvalue", typeU64},
		{"Starttime", typeU64},
		{"Vsize", typeU64},
		{"Rss", typeU64},
		{"Rsslim", typeU64},
		{"Startcode", typeU64},
		{"Endcode", typeU64},
		{"Startstack", typeU64},
		{"Kstkesp", typeU64},
		{"Kstkeip", typeU64},
		{"Signal", typeU64},
		{"Blocked", typeU64},
		{"Sigignore", typeU64},
		{"Sigcatch", typeU64},
		{"Wchan", typeU64},
		{"Nswap", typeU64},
		{"Cnswap", typeU64},
		{"ExitSignal", typeU64},
		{"Processor", typeU64},
		{"RtPriority", typeU64},
		{"Policy", typeU64},
		{"DelayacctBlkioTicks", typeU64},
		{"GuestTime", typeU64},
		{"CguestTime", typeU64},
		{"StartData", typeU64},
		{"EndData", typeU64},
		{"StartBrk", typeU64},
		{"ArgStart", typeU64},
		{"ArgEnd", typeU64},
		{"EnvStart", typeU64},
		{"EnvEnd", typeU64},
		{"ExitCode", typeU64},
	}
	var buf bytes.Buffer
	// gen type
	buf.WriteString("type procPidStat struct {")
	for _, v := range genTable {
		buf.WriteString("\n\t")
		buf.WriteString(v.name)
		buf.WriteString(" ")
		buf.WriteString(v.ftype)
	}
	buf.WriteString("\n}")
	// gen parser
	buf.WriteString(
		"\n\nfunc (p *procPidStat) Parse(items [][]byte) error {",
	)
	buf.WriteString("\n\tvar err error")
	fmt.Fprintf(&buf, "\n\tif len(items) != %d {", len(genTable))
	buf.WriteString("\n\t\treturn WrapMessage(\"bad stat items length\")")
	buf.WriteString("\n\t}")
	for i, v := range genTable {
		switch v.ftype {
		case typeU64:
			fmt.Fprintf(
				&buf,
				"\n\tp.%s, err = strconv.ParseUint(string(items[%d]), 10, 64)" +
				"\n\tif err != nil {" +
				"\n\t\treturn WrapMessage(\"%s: %%w\", err)" +
				"\n\t}",
				v.name,
				i,
				v.name,
			)
		case typeStr:
			fmt.Fprintf(
				&buf,
				"\n\tp.%s = string(items[%d])",
				v.name,
				i,
			)
		}
	}
	buf.WriteString("\n\treturn nil\n}")
	return buf.String()
}

type procPidStat struct {
	Pid uint64
	Comm string
	State string
	Ppid uint64
	Pgrp uint64
	Session uint64
	TtyNr uint64
	Tpgid uint64
	Flags uint64
	Minflt uint64
	Cminflt uint64
	Majflt uint64
	Cmajflt uint64
	Utime uint64
	Stime uint64
	Cutime uint64
	Cstime uint64
	Priority uint64
	Nice uint64
	NumThreads uint64
	Itrealvalue uint64
	Starttime uint64
	Vsize uint64
	Rss uint64
	Rsslim uint64
	Startcode uint64
	Endcode uint64
	Startstack uint64
	Kstkesp uint64
	Kstkeip uint64
	Signal uint64
	Blocked uint64
	Sigignore uint64
	Sigcatch uint64
	Wchan uint64
	Nswap uint64
	Cnswap uint64
	ExitSignal uint64
	Processor uint64
	RtPriority uint64
	Policy uint64
	DelayacctBlkioTicks uint64
	GuestTime uint64
	CguestTime uint64
	StartData uint64
	EndData uint64
	StartBrk uint64
	ArgStart uint64
	ArgEnd uint64
	EnvStart uint64
	EnvEnd uint64
	ExitCode uint64
}

func (p *procPidStat) Parse(items [][]byte) error {
	var err error
	if len(items) != 52 {
		return WrapMessage("bad stat items length")
	}
	p.Pid, err = strconv.ParseUint(string(items[0]), 10, 64)
	if err != nil {
		return WrapMessage("Pid: %w", err)
	}
	p.Comm = string(items[1])
	p.State = string(items[2])
	p.Ppid, err = strconv.ParseUint(string(items[3]), 10, 64)
	if err != nil {
		return WrapMessage("Ppid: %w", err)
	}
	p.Pgrp, err = strconv.ParseUint(string(items[4]), 10, 64)
	if err != nil {
		return WrapMessage("Pgrp: %w", err)
	}
	p.Session, err = strconv.ParseUint(string(items[5]), 10, 64)
	if err != nil {
		return WrapMessage("Session: %w", err)
	}
	p.TtyNr, err = strconv.ParseUint(string(items[6]), 10, 64)
	if err != nil {
		return WrapMessage("TtyNr: %w", err)
	}
	p.Tpgid, err = strconv.ParseUint(string(items[7]), 10, 64)
	if err != nil {
		return WrapMessage("Tpgid: %w", err)
	}
	p.Flags, err = strconv.ParseUint(string(items[8]), 10, 64)
	if err != nil {
		return WrapMessage("Flags: %w", err)
	}
	p.Minflt, err = strconv.ParseUint(string(items[9]), 10, 64)
	if err != nil {
		return WrapMessage("Minflt: %w", err)
	}
	p.Cminflt, err = strconv.ParseUint(string(items[10]), 10, 64)
	if err != nil {
		return WrapMessage("Cminflt: %w", err)
	}
	p.Majflt, err = strconv.ParseUint(string(items[11]), 10, 64)
	if err != nil {
		return WrapMessage("Majflt: %w", err)
	}
	p.Cmajflt, err = strconv.ParseUint(string(items[12]), 10, 64)
	if err != nil {
		return WrapMessage("Cmajflt: %w", err)
	}
	p.Utime, err = strconv.ParseUint(string(items[13]), 10, 64)
	if err != nil {
		return WrapMessage("Utime: %w", err)
	}
	p.Stime, err = strconv.ParseUint(string(items[14]), 10, 64)
	if err != nil {
		return WrapMessage("Stime: %w", err)
	}
	p.Cutime, err = strconv.ParseUint(string(items[15]), 10, 64)
	if err != nil {
		return WrapMessage("Cutime: %w", err)
	}
	p.Cstime, err = strconv.ParseUint(string(items[16]), 10, 64)
	if err != nil {
		return WrapMessage("Cstime: %w", err)
	}
	p.Priority, err = strconv.ParseUint(string(items[17]), 10, 64)
	if err != nil {
		return WrapMessage("Priority: %w", err)
	}
	p.Nice, err = strconv.ParseUint(string(items[18]), 10, 64)
	if err != nil {
		return WrapMessage("Nice: %w", err)
	}
	p.NumThreads, err = strconv.ParseUint(string(items[19]), 10, 64)
	if err != nil {
		return WrapMessage("NumThreads: %w", err)
	}
	p.Itrealvalue, err = strconv.ParseUint(string(items[20]), 10, 64)
	if err != nil {
		return WrapMessage("Itrealvalue: %w", err)
	}
	p.Starttime, err = strconv.ParseUint(string(items[21]), 10, 64)
	if err != nil {
		return WrapMessage("Starttime: %w", err)
	}
	p.Vsize, err = strconv.ParseUint(string(items[22]), 10, 64)
	if err != nil {
		return WrapMessage("Vsize: %w", err)
	}
	p.Rss, err = strconv.ParseUint(string(items[23]), 10, 64)
	if err != nil {
		return WrapMessage("Rss: %w", err)
	}
	p.Rsslim, err = strconv.ParseUint(string(items[24]), 10, 64)
	if err != nil {
		return WrapMessage("Rsslim: %w", err)
	}
	p.Startcode, err = strconv.ParseUint(string(items[25]), 10, 64)
	if err != nil {
		return WrapMessage("Startcode: %w", err)
	}
	p.Endcode, err = strconv.ParseUint(string(items[26]), 10, 64)
	if err != nil {
		return WrapMessage("Endcode: %w", err)
	}
	p.Startstack, err = strconv.ParseUint(string(items[27]), 10, 64)
	if err != nil {
		return WrapMessage("Startstack: %w", err)
	}
	p.Kstkesp, err = strconv.ParseUint(string(items[28]), 10, 64)
	if err != nil {
		return WrapMessage("Kstkesp: %w", err)
	}
	p.Kstkeip, err = strconv.ParseUint(string(items[29]), 10, 64)
	if err != nil {
		return WrapMessage("Kstkeip: %w", err)
	}
	p.Signal, err = strconv.ParseUint(string(items[30]), 10, 64)
	if err != nil {
		return WrapMessage("Signal: %w", err)
	}
	p.Blocked, err = strconv.ParseUint(string(items[31]), 10, 64)
	if err != nil {
		return WrapMessage("Blocked: %w", err)
	}
	p.Sigignore, err = strconv.ParseUint(string(items[32]), 10, 64)
	if err != nil {
		return WrapMessage("Sigignore: %w", err)
	}
	p.Sigcatch, err = strconv.ParseUint(string(items[33]), 10, 64)
	if err != nil {
		return WrapMessage("Sigcatch: %w", err)
	}
	p.Wchan, err = strconv.ParseUint(string(items[34]), 10, 64)
	if err != nil {
		return WrapMessage("Wchan: %w", err)
	}
	p.Nswap, err = strconv.ParseUint(string(items[35]), 10, 64)
	if err != nil {
		return WrapMessage("Nswap: %w", err)
	}
	p.Cnswap, err = strconv.ParseUint(string(items[36]), 10, 64)
	if err != nil {
		return WrapMessage("Cnswap: %w", err)
	}
	p.ExitSignal, err = strconv.ParseUint(string(items[37]), 10, 64)
	if err != nil {
		return WrapMessage("ExitSignal: %w", err)
	}
	p.Processor, err = strconv.ParseUint(string(items[38]), 10, 64)
	if err != nil {
		return WrapMessage("Processor: %w", err)
	}
	p.RtPriority, err = strconv.ParseUint(string(items[39]), 10, 64)
	if err != nil {
		return WrapMessage("RtPriority: %w", err)
	}
	p.Policy, err = strconv.ParseUint(string(items[40]), 10, 64)
	if err != nil {
		return WrapMessage("Policy: %w", err)
	}
	p.DelayacctBlkioTicks, err = strconv.ParseUint(string(items[41]), 10, 64)
	if err != nil {
		return WrapMessage("DelayacctBlkioTicks: %w", err)
	}
	p.GuestTime, err = strconv.ParseUint(string(items[42]), 10, 64)
	if err != nil {
		return WrapMessage("GuestTime: %w", err)
	}
	p.CguestTime, err = strconv.ParseUint(string(items[43]), 10, 64)
	if err != nil {
		return WrapMessage("CguestTime: %w", err)
	}
	p.StartData, err = strconv.ParseUint(string(items[44]), 10, 64)
	if err != nil {
		return WrapMessage("StartData: %w", err)
	}
	p.EndData, err = strconv.ParseUint(string(items[45]), 10, 64)
	if err != nil {
		return WrapMessage("EndData: %w", err)
	}
	p.StartBrk, err = strconv.ParseUint(string(items[46]), 10, 64)
	if err != nil {
		return WrapMessage("StartBrk: %w", err)
	}
	p.ArgStart, err = strconv.ParseUint(string(items[47]), 10, 64)
	if err != nil {
		return WrapMessage("ArgStart: %w", err)
	}
	p.ArgEnd, err = strconv.ParseUint(string(items[48]), 10, 64)
	if err != nil {
		return WrapMessage("ArgEnd: %w", err)
	}
	p.EnvStart, err = strconv.ParseUint(string(items[49]), 10, 64)
	if err != nil {
		return WrapMessage("EnvStart: %w", err)
	}
	p.EnvEnd, err = strconv.ParseUint(string(items[50]), 10, 64)
	if err != nil {
		return WrapMessage("EnvEnd: %w", err)
	}
	p.ExitCode, err = strconv.ParseUint(string(items[51]), 10, 64)
	if err != nil {
		return WrapMessage("ExitCode: %w", err)
	}
	return nil
}

func (p *procPidStat) Update(pid int) error {
	b, cerr := runCmd(fmt.Sprintf("cat /proc/%d/stat", pid))
	if cerr != nil {
		return cerr
	}
	b = bytes.Trim(b, " ")
	b = bytes.Trim(b, "\n")
	items := bytes.Split(b, []byte(" "))
	var p2 procPidStat
	err := p2.Parse(items)
	if err != nil {
		return Wrap(err)
	}
	*p = p2
	return nil
}

type procPidIo struct {
	rchar uint64
	wchar uint64
	syscr uint64
	syscw uint64
	read_bytes uint64
	write_bytes uint64
	cancelled_write_bytes uint64
}

func (i *procPidIo) Update(pid int) error {
	const ioStatNRow = 7
	const ioStatNCol = 2
	var r procPidIo
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

func (i *procPidIo) String() string {
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

func procRunning(pid int) bool {
	_, err := runCmd(fmt.Sprintf("kill -0 %d", pid))
	return err == nil
}

func procSignalSend(pid, signal int) bool {
	_, err := runCmd(fmt.Sprintf("kill %d %d", pid, signal))
	return err == nil
}

// SECTION_START node_common

type nodeOpts struct {
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
	https bool

	// args passed to the binary being executed
	binArgs []string

	description string

	// builder
	forceRebuild bool
}

func nodeRun(ctx context.Context, binPath string, opts nodeOpts) error {
	os.MkdirAll(opts.datadir, 0o755)

	log.Println("starting node with args: ", opts.binArgs)
	cmd := exec.Command(binPath, opts.binArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		return Wrap(err)
	}
	nodeDone := make(chan struct{})
	go func() {
		cmd.Wait()
		close(nodeDone)
	}()

	monitorDone := make(chan struct{})
	go func() {
		err = nodeMonitor(cmd.Process.Pid, opts)
		if err != nil {
			log.Println(Wrap(err))
		}
		close(monitorDone)
	}()

	select {
	case <-ctx.Done():
		cmd.Process.Signal(syscall.SIGTERM)
	case <-nodeDone:
	}
	<-nodeDone
	<-monitorDone
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		return WrapMessage("node exited with code %d", code)
	}
	return nil
}

type nodeStats struct {
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

func newNodeStats(obs string) *nodeStats {
	return &nodeStats{
		StartTs: time.Now().Unix(),
		Obs: obs,
	}
}

func (s *nodeStats) update(
	pid int, nodeRpcUrl, nodeRpcUser, nodeRpcPassword, dataDir string,
) error {
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

	pageSize, err := pageSize()
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
	var ps procPidStat
	err = ps.Update(pid)
	if err != nil {
		return Wrap(err)
	}
	s.VMbytes = ps.Vsize
	s.VMmaxBytes = max(s.VMmaxBytes, s.VMbytes)
	s.RSSbytes = ps.Rss*pageSize
	s.RSSmaxBytes = max(s.RSSmaxBytes, s.RSSbytes)
	s.CPUuserNS = ps.Utime*clockTickMul
	s.CPUsystemNS = ps.Stime*clockTickMul

	// I/O stats
	var ios procPidIo
	err = ios.Update(pid)
	if err != nil {
		return Wrap(err)
	}
	s.StorageReadBytes = ios.read_bytes
	s.StorageWriteBytes = ios.write_bytes
	s.RcharBytes = ios.rchar
	s.WcharBytes = ios.wchar

	dataDirSize, err := dirSizeBytes(dataDir)
	if err != nil && strings.Contains(err.Error(), ".ldb") {
		// ignore
	} else if err != nil {
		log.Println(WrapMessage("failed to get data size: %w", err))
	} else {
		s.DataStoreSizeBytes = dataDirSize
	}

	// height tracking
	h, err := nodeFetchBlockCount(nodeRpcUrl, nodeRpcUser, nodeRpcPassword)
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

func nodeFetchBlockCount(nodeRpcURL, rpcUser, rpcPassword string) (int, error) {
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
	req, err := http.NewRequest("POST", nodeRpcURL, &reqBody)
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

func nodeMonitor(
	pid int,
	opts nodeOpts,
) error {
	checkInterval := time.Second * 1
	stats := newNodeStats(
		fmt.Sprintf(
			"mempool_mb=%d" +
			" utxocache_mb=%d" +
			" assumevalid=%s" +
			" noassumevalid=%t" +
			" desc=%s",
			opts.mempoolMB,
			opts.utxoCacheMB,
			opts.checkpoint,
			opts.nocheckpoint,
			opts.description,
		),
	)
	for procRunning(pid) {
		urlPrefix := "http://"
		if opts.https {
			urlPrefix = "https://"
		}
		err := stats.update(
			pid,
			urlPrefix+opts.rpcListenAddr,
			opts.rpcuser,
			opts.rpcpassword,
			opts.datadir,
		)
		if err != nil {
			log.Println(Wrap(err))
		}
		if opts.stopHeight > 0 &&
		stats.CurrentHeight >= opts.stopHeight {
			procSignalSend(pid, int(syscall.SIGTERM))
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

// SECTION_START btcd

func btcdBuild(opts btcdOpts) error {
	const btcdRepoUrl = "https://github.com/allocz/btcd"
	// const btcdRepoBranch = "checkpoint_no_prevout_disk_lookup"
	const btcdRepoBranch = "master"
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

type btcdOpts nodeOpts

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
	o.https = true
	o.binArgs = binArgs
	return nil
}

func btcdCommand(ctx context.Context, args []string) error {
	var opts btcdOpts
	err := opts.ParseFlags(args[:])
	if err != nil {
		return Wrap(err)
	}
	err = btcdBuild(opts)
	if err != nil {
		return Wrap(err)
	}
	err = nodeRun(
		ctx,
		"data/btcd",
		nodeOpts(opts),
	)
	if err != nil {
		return Wrap(err)
	}
	return nil
}

// SECTION_START bitcoind

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

type bitcoindOpts nodeOpts

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

func bitcoindCommand(ctx context.Context, args []string) error {
	var opts bitcoindOpts
	err := opts.ParseFlags(args[:])
	if err != nil {
		return Wrap(err)
	}
	err = bitcoindDownload(opts)
	if err != nil {
		return Wrap(err)
	}
	err = nodeRun(
		ctx,
		"data/bitcoind/bin/bitcoind",
		nodeOpts(opts),
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
