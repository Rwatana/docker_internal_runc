#ifndef NSEXEC_H
#define NSEXEC_H

#include <setjmp.h>
#include <stdint.h>

#define STAGE_SETUP -1
#define STAGE_PARENT 0
#define STAGE_CHILD 1
#define STAGE_INIT 2

#define CLONE_FLAGS_ATTR 27281

static int syncfd = -1;

/* Assume the stack grows down, so arguments should be above it. */
struct clone_t {
  /*
   * Reserve some space for clone() to locate arguments
   * and retcode in this place
   */
  char stack[4096] __attribute__((aligned(16)));
  char stack_ptr[0];

  /* There's two children. This is used to execute the different code. */
  jmp_buf *env;
  int jmpval;
};

enum sync_t {
	SYNC_USERMAP_PLS = 0x40,	/* Request parent to map our users. */
	SYNC_USERMAP_ACK = 0x41,	/* Mapping finished by the parent. */
	SYNC_RECVPID_PLS = 0x42,	/* Tell parent we're sending the PID. */
	SYNC_RECVPID_ACK = 0x43,	/* PID was correctly received by parent. */
	SYNC_GRANDCHILD = 0x44,	/* The grandchild is ready to run. */
	SYNC_CHILD_FINISH = 0x45,	/* The child or grandchild has finished. */
	SYNC_MOUNTSOURCES_PLS = 0x46,	/* Tell parent to send mount sources by SCM_RIGHTS. */
	SYNC_MOUNTSOURCES_ACK = 0x47,	/* All mount sources have been sent. */
};

int current_stage = STAGE_SETUP;

struct nlconfig_t {
  char *data;

  /* Process settings. */
  uint32_t cloneflags;
};

int clone_parent(jmp_buf *env, int jmpval);

#endif  // NSEXEC_H