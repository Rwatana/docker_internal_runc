# nsexec

## What is nsexec
nsexec is a component of runc that allows you to execute a program in a namespace of a running container. It allows you to enter the namespace of a container and execute a program as if it were running inside the container. nsexec works by making a series of system calls to the Linux kernel to switch to the namespace of the container and execute the program.

## Implement of the nsexec

Toy case of nsexec consists of two function which are child_func and clone_parent. Also, these corresponding test codes describe how to use clone_parent function.

### child_func (src/nsexec.c)
The child_func is a static function that takes a void pointer arg as an argument. It casts the void pointer arg to a struct clone_t type pointer ca, which holds the values of a jmp_buf and an integer.

The child_func calls the longjmp function and passes the jmp_buf value from the ca structure and the jmpval value, which is used to specify the value to be returned by setjmp in a different execution context. This function is used as the entry point for a new process created by the clone function.

### clone_parent (src/nsexec.c)
The clone_parent function takes two arguments, a jmp_buf pointer env and an integer jmpval. The function creates a struct clone_t type ca and initializes its members env and jmpval with the arguments passed to clone_parent.

The clone function is then called with the child_func function as the first argument, the address of ca.stack_ptr as the second argument, and the flags CLONE_PARENT and SIGCHLD as the third argument. The fourth argument is the address of the ca structure, which is passed as an argument to the child_func function.

The clone function creates a new process and the return value of clone is the process ID of the new process in the parent process, or 0 in the child process. The clone function and clone_parent function together allow for creating a new process and sharing the memory space, file descriptors, and signal handlers with the parent process.

### Test codes of clone_parent (tests/C/main.cpp)
The purpose of this test is to verify the behavior of a clone_parent function and the system calls it uses. The jmp_buf variable env and the integer variables ok, current_stage, and syncfd are used to store the state and results of the test. The sync_pipe array is used to create a socket pair for inter-process communication.

In the STAGE_PARENT case of the switch statement, a child process is created using the clone_parent function and passed the address of the env buffer. The parent process then opens the sync_pipe for writing and closes the end for reading. The parent reads the process ID from the child process, which is written to the sync_pipe, and performs a series of checks to verify the correct behavior.

In the STAGE_CHILD case, the child process opens the sync_pipe for reading and closes the end for writing. The child process creates a new user namespace using the unshare system call with the CLONE_NEWUSER flag, which allows the child to have a separate user and group ID namespace from its parent. The child process then writes its process ID to the sync_pipe and terminates.

The EXPECT_GE and EXPECT_EQ macros are used to verify the results of the test and report failure if any of the expectations are not met. The exit function is used to exit the child process with a status of 0.

### How to test
Set up the environment by following steps.
```
$ git clone https://github.com/nayuta-ai/docker_internal.git
$ cd docker_internal
$ git fetch
$ git checkout nsexec/clone_parent
$ make build
$ make run
$ make exec
```

Test the nsexec script by following steps.
```
$ cd nsexec
$ mkdir build
$ cd build
$ cmake ..
$ make
$ cd test
$ ./nsexec_test
```

## How to use isolated namespace using nsexec
### How to use nsenter using cgo
The nsenter package registers a special init constructor that is called before the Go runtime has a chance to boot. This provides us the ability to setns on existing namespaces and avoid the issues that the Go runtime has with multiple threads. This constructor will be called if this package is registered, imported, in your go application.

The nsenter package will import "C" and it uses cgo package. In cgo, if the import of "C" is immediately preceded by a comment, that comment, called the preamble, is used as a header when compiling the C parts of the package. So every time we import package nsenter, the C code function nsexec() would be called. And package nsenter is only imported in init.go, so every time the runc init command is invoked, that C code is run.

Because nsexec() must be run before the Go runtime in order to use the Linux kernel namespace, you must import this library into a package if you plan to use libcontainer directly. Otherwise Go will not execute the nsexec() constructor, which means that the re-exec will not cause the namespaces to be joined. You can import it like this:
```
import _ "github.com/opencontainers/runc/libcontainer/nsenter"
```

### Test codes of nsexec function
This time doesn't show the explanation of nsexec function because it is complicated to explain how to run nsexec. If anyone wants to know the overview of nsexec function, please see [nsexec.c](../nsexec/nsexec.c)

`nsexec.go` is a Go file that includes a C code snippet using cgo. The purpose of this file is to include a C function nsexec() in the compiled Go binary.
This file serves as a bridge between the Go and C languages, allowing the Go program to call C functions and interact with the operating system at a lower level.

`nsexec_test.go` contains a Go test function that tests the functionality of the `nsenter-exec` command. The test function starts by creating a new socket pair for communicating with the `nsexec` function using the `newPipe` function:
```
parent, child := newPipe(t)
```
Next, the `cmd.Start()` function is called to execute the `nsenter-exec` command. This causes the program to jump to the `init()` function in `nsexec.go`, which in turn executes the `nsexec` function.
Next, the `io.Copy(parent, bytes.NewReader(r.Serialize()))` pass config information to `nsexec` function and `initWaiter(t, parent)` is used to synchronize the parent and child processes by waiting for the child process to complete its initialization before continuing with the test.
Next, `cmd.Wait()` is used to check whether the nsenter-exec command completed successfully or failed, and to report any errors that occurred during execution. If an error occurred, the test fails.
Finally, `reapChildren(t, parent)` is used to reap child processes after the nsenter-exec command has completed.

### How to test
Set up the environment by following steps.
```
$ git clone https://github.com/nayuta-ai/docker_internal.git
$ cd docker_internal
$ git fetch
$ git checkout nsexec/cgo
$ make build
$ make run
$ make exec
```

Test the `nsenter_test.go` by following steps.
```
$ cd nsexec
$ go test .
```