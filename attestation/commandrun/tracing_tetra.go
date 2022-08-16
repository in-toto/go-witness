package commandrun

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/log"

	"github.com/cilium/tetragon/api/v1/tetragon"

	cillium "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type fileInfos struct {
	fileInfos map[string]*FileInfo
	mutex     sync.RWMutex
}

type processInfos struct {
	processInfos []*ProcessInfo
	mutex        sync.RWMutex
}

func GetDescendentPIDs(parentPID uint, decedents []uint, allPIDs []uint) []uint {
	for i, pid := range allPIDs {
		if pid == parentPID {
			decedents = append(decedents, pid)
			decedents = GetDescendentPIDs(pid, decedents, allPIDs[i+1:])
		}
	}
	return decedents
}

type socketInfos struct {
	socketInfos map[string]*SocketInfo
	mutex       sync.RWMutex
}

type TraceContext struct {
	pi       processInfos
	fi       fileInfos
	si       socketInfos
	ctx      *attestation.AttestationContext
	pid      int
	done     chan bool
	policies []*Policy
	client   tetragon.FineGuidanceSensorsClient
	cr       *CommandRun
}

func NewTC(ctx *attestation.AttestationContext, cr *CommandRun, pid int) (*TraceContext, error) {
	tc := TraceContext{
		pi:       processInfos{processInfos: []*ProcessInfo{}},
		fi:       fileInfos{fileInfos: make(map[string]*FileInfo)},
		si:       socketInfos{socketInfos: make(map[string]*SocketInfo)},
		ctx:      ctx,
		done:     make(chan bool),
		policies: []*Policy{},
		client:   nil,
		cr:       cr,
		pid:      pid,
	}

	tc.policies = append(tc.policies, GetKProbePolicy(uint(pid), cr.tetragonWatchPrefix))

	binary, err := os.Readlink("/proc/" + fmt.Sprintf("%d", pid) + "/exe")
	if err != nil {
		return nil, err
	}

	var argsStr string
	args, err := os.ReadFile("/proc/" + fmt.Sprintf("%d", pid) + "/cmdline")
	if err == nil {
		argsStr = cleanString(string(args))
		argsSlice := strings.Split(argsStr, " ")
		//remove first entry which is the binary name
		argsSlice = argsSlice[1:]
		argsStr = strings.Join(argsSlice, " ")
	}

	digest, err := cryptoutil.CalculateDigestSetFromFile(binary, tc.ctx.Hashes())
	if err != nil {
		return nil, err
	}

	firstEvent := &ProcessInfo{
		Binary:           binary,
		Args:             argsStr,
		ProcessID:        pid,
		ParentPID:        cr.WitnessPID,
		BinaryDigest:     digest,
		StartTime:        time.Now().UTC(),
		StopTime:         time.Time{},
		UID:              os.Getuid(),
		Environ:          "",
		Flags:            "",
		processEventType: "",
	}

	tc.pi.processInfos = append(tc.pi.processInfos, firstEvent)

	return &tc, nil
}

type Policy struct {
	Kind       string                    `json:"kind"`
	APIVersion string                    `json:"apiVersion"`
	Metadata   MetaData                  `json:"metadata"`
	Spec       cillium.TracingPolicySpec `json:"spec"`
}

type MetaData struct {
	Name string `json:"name"`
}

func NewClient(ctx context.Context, serverAddress string) (tetragon.FineGuidanceSensorsClient, error) {
	connCtx, connCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connCancel()
	conn, err := grpc.DialContext(connCtx, serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Errorf("Failed to dial tetragon server: %s", err)
		return nil, err
	}

	c := tetragon.NewFineGuidanceSensorsClient(conn)
	return c, nil
}

func (tc *TraceContext) Stop(cr *CommandRun) error {
	err := tc.RemoveAllTraces()
	if err != nil {
		return err
	}

	tc.done <- true

	return nil
}

func (tc *TraceContext) Start() error {
	c, err := NewClient(tc.ctx.Context(), tc.cr.tetragonAddress)
	if err != nil {
		return err
	}

	tc.client = c

ADD_POLICY:
	for _, p := range tc.policies {
		j, err := json.Marshal(p)
		if err != nil {
			return err
		}

		_, err = tc.client.AddTracingPolicy(tc.ctx.Context(), &tetragon.AddTracingPolicyRequest{
			Yaml: string(j),
		})
		//remove sensor in case it didn't get cleaned up
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				RemoveTrace(tc.ctx.Context(), tc.client, p.Metadata.Name)
				goto ADD_POLICY
			} else {
				return err
			}
		}
	}

	events := make(chan *tetragon.GetEventsResponse, 1000)
	go tc.GetEvents(events)
	go tc.ProcessEvents(events)
	return nil
}

func (tc *TraceContext) RemoveAllTraces() error {
	names := []string{}
	for _, p := range tc.policies {
		names = append(names, p.Metadata.Name)
	}

	for _, name := range names {
		err := RemoveTrace(tc.ctx.Context(), tc.client, name)
		if err != nil {
			return err
		}
	}
	return nil
}

func RemoveTrace(ctx context.Context, client tetragon.FineGuidanceSensorsClient, policyName string) error {
	_, err := client.DisableSensor(ctx, &tetragon.DisableSensorRequest{
		Name: policyName,
	})

	if err != nil {
		return err
	}

	_, err = client.RemoveSensor(ctx, &tetragon.RemoveSensorRequest{
		Name: policyName,
	})

	if err != nil {
		return err
	}

	return nil
}

func (tc *TraceContext) ProcessSocketEvent(e *tetragon.ProcessKprobe, t time.Time) {
	sa := e.Args[0].GetSockArg()

	access := SocketAccess{
		ProcessPID: int(e.Process.Pid.Value),
		Time:       t,
		Type:       AccessTypeOpen,
	}

	tc.si.mutex.Lock()
	defer tc.si.mutex.Unlock()
	if _, ok := tc.si.socketInfos[sa.Daddr]; ok {
		tc.si.socketInfos[sa.Daddr].SocketAccess = append(tc.si.socketInfos[sa.Daddr].SocketAccess, access)
	} else {
		tc.si.socketInfos[sa.Daddr] = &SocketInfo{
			RemoteAddress: sa.Daddr,
			LocalAddress:  sa.Saddr,
			LocalPort:     int(sa.Sport),
			RemotePort:    int(sa.Dport),
			SocketType:    "tcp",
			SocketAccess: []SocketAccess{
				access,
			},
		}
	}
}

func (tc *TraceContext) ProcessKprobe(e *tetragon.ProcessKprobe, t time.Time) {
	switch e.FunctionName {
	case "tcp_connect":
		tc.ProcessSocketEvent(e, t)
	case "fd_install":
		go tc.ProcessFileEvent(e, t)
	case "__x64_sys_close":
		go tc.ProcessFileEvent(e, t)
	case "__x64_sys_write":
		go tc.ProcessFileEvent(e, t)
	case "__x64_sys_read":
		go tc.ProcessFileEvent(e, t)
	}

}

func (tc *TraceContext) ProcessFileEvent(e *tetragon.ProcessKprobe, t time.Time) {
	if int(e.Process.Pid.Value) == tc.cr.WitnessPID {
		return
	}

	path := ""

	var eventType AccessType
	switch e.FunctionName {
	case "fd_install":
		path = e.Args[1].GetFileArg().Path
		eventType = AccessTypeOpen
	case "__x64_sys_close":
		path = e.Args[0].GetFileArg().Path
		eventType = AccessTypeClose
	case "__x64_sys_write":
		path = e.Args[0].GetFileArg().Path
		eventType = AccessTypeWrite
	case "__x64_sys_read":
		path = e.Args[0].GetFileArg().Path
		eventType = AccessTypeRead
	}

	if path == "" {

		return
	}

	var digest cryptoutil.DigestSet

	if eventType == "open" || eventType == "close" {
		if path == "" {
			return
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			return
		}

		if fileInfo.IsDir() {
			return
		}

		if fileInfo.Mode().IsRegular() {
			digest, err = cryptoutil.CalculateDigestSetFromFile(path, tc.ctx.Hashes())
			if err != nil {
				log.Errorf("Error calculating digest for file %s: %s", path, err)
			}
		}
	}

	fileAccess := FileAccess{
		ProcessPID: int(e.Process.Pid.Value),
		Time:       t,
		AccessType: eventType,
		Digest:     digest,
	}

	tc.fi.mutex.Lock()

	if fi, ok := tc.fi.fileInfos[path]; !ok {
		tc.fi.fileInfos[path] = &FileInfo{
			Path:   path,
			Access: []FileAccess{fileAccess},
		}
	} else {
		fi.Access = append(fi.Access, fileAccess)
	}

	tc.fi.mutex.Unlock()

}

func (tc *TraceContext) storeProcessExitEvent(e *tetragon.ProcessExit, eventTime time.Time) {
	ppid := -1

	if e.Parent != nil {
		ppid = int(e.Parent.Pid.Value)
	}

	newProcessInfo := ProcessInfo{
		Binary:           e.Process.Binary,
		BinaryDigest:     nil,
		Args:             e.Process.Arguments,
		ProcessID:        int(e.Process.Pid.Value),
		ParentPID:        ppid,
		Environ:          "",
		StartTime:        time.Time{},
		StopTime:         eventTime,
		UID:              int(e.Process.Uid.GetValue()),
		Flags:            e.Process.Flags,
		processEventType: EventTypeExit,
	}

	tc.pi.mutex.Lock()
	defer tc.pi.mutex.Unlock()
	tc.pi.processInfos = append(tc.pi.processInfos, &newProcessInfo)

}

func (tc *TraceContext) storeProcessExecEvent(e *tetragon.ProcessExec) {
	if int(e.Process.Pid.Value) == tc.pid {
		log.Debugf("Pid: %d, Binary: %s, Args: %s", e.Process.Pid.Value, e.Process.Binary, e.Process.Arguments)
	}

	if e.Parent == nil {
		log.Debugf("Nil Parent: Pid: %d, Binary: %s, Args: %s", e.Process.Pid.Value, e.Process.Binary, e.Process.Arguments)
		return
	}

	digest, err := cryptoutil.CalculateDigestSetFromFile(e.Process.Binary, tc.ctx.Hashes())
	if err != nil {
		log.Errorf("Error calculating digest for %s: %s", e.Process.Binary, err)
	}

	newProcessInfo := ProcessInfo{
		Binary:           e.Process.Binary,
		BinaryDigest:     digest,
		Args:             e.Process.Arguments,
		ProcessID:        int(e.Process.Pid.Value),
		ParentPID:        int(e.Parent.Pid.Value),
		Environ:          "",
		StartTime:        e.Process.StartTime.AsTime(),
		StopTime:         time.Time{},
		UID:              int(e.Process.Uid.GetValue()),
		Flags:            e.Process.Flags,
		processEventType: EventTypeExec,
	}

	tc.pi.mutex.Lock()
	defer tc.pi.mutex.Unlock()
	tc.pi.processInfos = append(tc.pi.processInfos, &newProcessInfo)

}

func (tc *TraceContext) ProcessEvents(events chan *tetragon.GetEventsResponse) {
	for r := range events {

		if r == nil {
			return
		}

		switch r.Event.(type) {
		case *tetragon.GetEventsResponse_ProcessExec:
			e := r.GetProcessExec()
			go tc.storeProcessExecEvent(e)

		case *tetragon.GetEventsResponse_ProcessKprobe:
			e := r.GetProcessKprobe()
			go tc.ProcessKprobe(e, r.Time.AsTime())

		case *tetragon.GetEventsResponse_ProcessTracepoint:
			log.Debugf("Unsupported Tracepoint event: %v", r.GetProcessTracepoint())

		case *tetragon.GetEventsResponse_ProcessExit:
			e := r.GetProcessExit()
			go tc.storeProcessExitEvent(e, r.Time.AsTime())

		default:
			log.Debugf("Unknown event: %v", r.Event)

		}
	}
}

func (tc *TraceContext) GetEvents(events chan *tetragon.GetEventsResponse) error {
	log.Info("Getting BPF Events from Tetragon")
	stream, err := tc.client.GetEvents(tc.ctx.Context(), &tetragon.GetEventsRequest{})
	if err != nil {
		return err
	}

	for {
		r, err := stream.Recv()
		if err != nil {
			return err
		}

		select {
		case events <- r:
		case <-tc.done:
			stream.Context().Done()
			tc.pi.mutex.RLock()
			defer tc.pi.mutex.RUnlock()

			procInfo := tc.pi.processInfos

			descendent := make([]*ProcessInfo, 0)

			//Grab everything with a parent pid of self (witness)
			for _, p := range procInfo {
				if p.ParentPID == int(tc.cr.WitnessPID) {
					descendent = append(descendent, p)
				}
			}

			//Grab everything with a parent pid of the descendent
			for _, p := range procInfo {
				for _, d := range descendent {
					if p.ParentPID == d.ProcessID {
						descendent = append(descendent, p)

					}
				}
			}

			cleaned := make([]*ProcessInfo, 0)

			//Get stop time for each descendent
			for _, p := range descendent {
				for _, d := range descendent {
					if p.StopTime.IsZero() && p.ProcessID == d.ProcessID {
						p.StopTime = d.StopTime
						cleaned = append(cleaned, p)
					}
				}
			}

			for _, p := range cleaned {
				tc.cr.Processes = append(tc.cr.Processes, *p)
			}

			for _, s := range tc.si.socketInfos {
				tc.cr.Sockets = append(tc.cr.Sockets, *s)
			}

			for _, fi := range tc.fi.fileInfos {
				for _, f := range fi.Access {
					if !contains(fi.PIDs, f.ProcessPID) {
						fi.PIDs = append(fi.PIDs, f.ProcessPID)
					}
				}

			}

			for _, fi := range tc.fi.fileInfos {

				tc.cr.Files = append(tc.cr.Files, *fi)

			}

		}
	}
}

func GetKProbePolicy(pid uint, paths []string) *Policy {
	tcpConnectSpec := cillium.KProbeSpec{
		Call:    "tcp_connect",
		Return:  false,
		Syscall: false,
		Args: []cillium.KProbeArg{
			{
				Index: 0,
				Type:  "sock",
			},
		},
		Selectors: []cillium.KProbeSelector{
			{
				MatchPIDs: []cillium.PIDSelector{
					{
						FollowForks: true,
						Operator:    "In",
						Values:      []uint32{uint32(pid)},
					},
				},
			},
		},
	}

	fdInstallProc := cillium.KProbeSpec{
		Call:    "fd_install",
		Return:  false,
		Syscall: false,
		Args: []cillium.KProbeArg{
			{
				Index: 0,
				Type:  "int",
			},
			{
				Index: 1,
				Type:  "file",
			},
		},
		Selectors: []cillium.KProbeSelector{
			{
				MatchPIDs: []cillium.PIDSelector{
					{
						FollowForks: true,
						Operator:    "In",
						Values:      []uint32{uint32(pid)},
					},
				},
			},
		},
	}

	fdInstallPath := cillium.KProbeSpec{
		Call:    "fd_install",
		Syscall: false,
		Args: []cillium.KProbeArg{
			{
				Index: 0,
				Type:  "int",
			},
			{
				Index: 1,
				Type:  "file",
			},
		},
		ReturnArg: cillium.KProbeArg{},
		Selectors: []cillium.KProbeSelector{
			{
				MatchActions: []cillium.ActionSelector{
					{
						Action:  "FollowFD",
						ArgFd:   0,
						ArgName: 1,
					},
				},

				MatchArgs: []cillium.ArgSelector{
					{
						Operator: "Prefix",
						Index:    1,
						Values:   paths,
					},
				},
			},
		},
	}

	sysCloseSpec := cillium.KProbeSpec{
		Call:    "__x64_sys_close",
		Syscall: true,
		Args: []cillium.KProbeArg{
			{
				Index: 0,
				Type:  "fd",
			},
		},
		Selectors: []cillium.KProbeSelector{
			{
				MatchActions: []cillium.ActionSelector{
					{
						Action:  "UnfollowFD",
						ArgFd:   0,
						ArgName: 0,
					},
				},
			},
		},
	}

	specKprobe := &cillium.TracingPolicySpec{
		KProbes: []cillium.KProbeSpec{tcpConnectSpec, fdInstallPath, sysCloseSpec, fdInstallProc},
	}

	return &Policy{
		Kind:       "TracingPolicy",
		APIVersion: "cilium.io/v1alpha1",
		Metadata:   MetaData{Name: "witness-trace-kprobe"},
		Spec:       *specKprobe,
	}
}

func contains(i []int, j int) bool {
	for _, v := range i {
		if v == j {
			return true
		}
	}

	return false
}
