#include <gtest/gtest.h>
#include <setjmp.h>
#include <sys/socket.h>

extern "C" {
#include "nsexec.h"
}

TEST(CloneParentTest, BasicTest) {
  jmp_buf env;
  int ok, current_stage;
  int syncfd;
  int sync_pipe[2];

  /* Create a socket that connects STAGE_PARENT and STAGE_CHILD */
  ok = socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_pipe);
  EXPECT_GE(ok, 0);

  current_stage = setjmp(env);
  switch (current_stage) {
    case STAGE_PARENT: {
      pid_t child_pid = -1, pid_from_child;
      int size;

      // Create child process
      child_pid = clone_parent(&env, STAGE_CHILD);
      // Open sync_pipe
      syncfd = sync_pipe[1];
      ok = close(sync_pipe[0]);
      EXPECT_GE(ok, 0);
      size = read(syncfd, &pid_from_child, sizeof(pid_t));
      EXPECT_EQ(size, sizeof(pid_t));
      EXPECT_EQ(pid_from_child, child_pid);
      EXPECT_NE(getpid(), pid_from_child);
      EXPECT_EQ(getpid(), pid_from_child - 1);
    } break;

    case STAGE_CHILD: {
      int size;
      pid_t process_id;
      /* We're in a child and thus need to tell the parent if we die. */
      syncfd = sync_pipe[0];
      ok = close(sync_pipe[1]);
      EXPECT_GE(ok, 0);
      /* Create new user namespace. */
      ok = unshare(CLONE_NEWUSER);
      EXPECT_GE(ok, 0);
      process_id = getpid();
      size = write(syncfd, &process_id, sizeof(pid_t));
      EXPECT_EQ(size, sizeof(pid_t));
      exit(0);
    } break;
  }
}
