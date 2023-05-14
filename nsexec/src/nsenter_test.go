package nsenter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func TestNsenterBasic(t *testing.T) {
	args := []string{"nsenter-exec"}
	parent, child := newPipe(t)

	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       args,
		ExtraFiles: []*os.File{child},
		Env:        []string{"_LIBCONTAINER_INITPIPE=3"},
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("nsenter failed to start: %v", err)

	}
	child.Close()
	t.Error("child is finished")

	// Format new net link request corresponding to the message
	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Int32msg{
		Type:  libcontainer.CloneFlagsAttr,
		Value: uint32(unix.CLONE_NEWUSER),
	})

	if _, err := io.Copy(parent, bytes.NewReader(r.Serialize())); err != nil {
		t.Fatal(err)
	}

	initWaiter(t, parent)

	if err := cmd.Wait(); err != nil {
		t.Fatalf("nsenter error: %v", err)
	}

	// reapChildren(t, parent)
}

func init() {
	if strings.HasPrefix(os.Args[0], "nsenter-") {
		os.Exit(0)
	}
}

// newPipe creates new socket pair.
func newPipe(t *testing.T) (parent *os.File, child *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("socketpair failed:", err)
	}
	parent = os.NewFile(uintptr(fds[1]), "parent")
	child = os.NewFile(uintptr(fds[0]), "child")
	t.Cleanup(func() {
		parent.Close()
		child.Close()
	})
	return
}

// initWaiter reads back the initial \0 from runc init
func initWaiter(t *testing.T, r io.Reader) {
	inited := make([]byte, 1)
	n, err := r.Read(inited)
	if err == nil {
		if n < 1 {
			err = errors.New("short read")
		} else if inited[0] != 0 {
			err = fmt.Errorf("unexpected %d != 0", inited[0])
		} else {
			return
		}
	}
	t.Fatalf("waiting for init preliminary setup: %v", err)
}

func reapChildren(t *testing.T, parent *os.File) {
	t.Helper()
	decoder := json.NewDecoder(parent)
	decoder.DisallowUnknownFields()
	var pid struct {
		Pid2 int `json:"stage2_pid"`
		Pid1 int `json:"stage1_pid"`
	}
	if err := decoder.Decode(&pid); err != nil {
		t.Fatal(err)
	}

	// Reap children.
	_, _ = unix.Wait4(pid.Pid1, nil, 0, nil)
	_, _ = unix.Wait4(pid.Pid2, nil, 0, nil)

	// Sanity check.
	if pid.Pid1 == 0 || pid.Pid2 == 0 || pid.Pid1 == pid.Pid2 {
		t.Fatal("got pids:", pid)
	}
}
