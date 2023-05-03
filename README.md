# docker_internal_runc

## runc
### What is runc
runc is an open-source implementation of the Open Container Initiative (OCI) runtime specification. It provides a standard interface for executing containers on a host, including launching and managing containers, setting up storage, networking, and executing commands within the container. runc is used by many popular container platforms and orchestration systems, including Docker, Kubernetes, and OpenShift.

In this tutorial, we will demonstrate how to implement the runc. Don't worry if you don't understand something, as this tutorial will guide you through the implementation process step by step and provide you with easy to follow instructions using C and Go.

### How to create runc binary

1. Implement the OCI runtime specification: The OCI runtime specification defines the interface between runtimes (such as runc) and the components that orchestrate containers (such as a container engine).

2. Create the process and namespace isolation: This involves using system calls such as unshare, setns, clone, and execve to create isolated namespaces for the container process, such as a new mount namespace, UTS namespace, PID namespace, and network namespace.

3. Configure control groups (cgroups): Use the cgroup system calls to limit the resources (such as CPU, memory, and I/O bandwidth) that the container process can access.

4. Configure network: Use the network namespace system calls to create a virtual network stack for the container process, with its own virtual Ethernet device, IP address, and routing table.

5. Start the process: Use execve to start the process specified in the OCI configuration file inside the container namespace.

## Overview
- [nsenter](doc/nsenter.md)