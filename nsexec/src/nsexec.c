#define _GNU_SOURCE
#include "../include/nsexec.h"
#include <errno.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>

#include "../include/namespace.h"


static uint32_t readint32(char *buf) { return *(uint32_t *)buf; }

static inline int sane_kill(pid_t pid, int signum)
{
	if (pid > 0)
		return kill(pid, signum);
	else
		return 0;
}

int child_func(void *arg) {
  struct clone_t *ca = (struct clone_t *)arg;
  longjmp(*ca->env, ca->jmpval);
}

int clone_parent(jmp_buf *env, int jmpval) {
  struct clone_t ca = {
      .env = env,
      .jmpval = jmpval,
  };
  return clone(child_func, ca.stack_ptr, CLONE_PARENT | SIGCHLD, &ca);
}

/*
 * Log levels are the same as in logrus.
 */
#define PANIC 0
#define FATAL 1
#define ERROR 2
#define WARNING 3
#define INFO 4
#define DEBUG 5
#define TRACE 6

static const char *level_str[] = {"panic", "fatal", "error", "warning",
                                  "info",  "debug", "trace"};

static int logfd = -1;
static int loglevel = DEBUG;

void write_log(int level, const char *format, ...) {
  char *message = NULL, *stage = NULL, *json = NULL;
  va_list args;
  int ret;

  if (logfd < 0 || level > loglevel) {
    goto out;
  }

  va_start(args, format);
  ret = vasprintf(&message, format, args);
  va_end(args);
  if (ret < 0) {
    message = NULL;
    goto out;
  }

  // message = escape_json_string(message);

  if (current_stage == STAGE_SETUP) {
    stage = strdup("nsexec");
    if (stage == NULL) goto out;
  } else {
    ret = asprintf(&stage, "nsexec-%d", current_stage);
    if (ret < 0) {
      stage = NULL;
      goto out;
    }
  }
  ret = asprintf(&json, "{\"level\":\"%s\", \"msg\": \"%s[%d]: %s\"}\n",
                 level_str[level], stage, getpid(), message);
  if (ret < 0) {
    json = NULL;
    goto out;
  }
  /* This logging is on a best-effort basis. In case of a short or failed
   * write there is nothing we can do, so just ignore write() errors.
   */
  ssize_t __attribute__((unused)) __res = write(logfd, json, ret);

out:
  free(message);
  free(stage);
  free(json);
}

#define bail(fmt, ...)                                        \
  do {                                                        \
    if (logfd < 0)                                            \
      fprintf(stderr, "FATAL: " fmt ": %m\n", ##__VA_ARGS__); \
    else                                                      \
      write_log(DEBUG, fmt ": %m");                           \
    exit(1);                                                  \
  } while (0)



static int getenv_int(const char *name) {
  char *val, *endptr;
  int ret;

  val = getenv(name);
  /* Treat empty value as unset variable. */
  if (val == NULL || *val == '\0') return -ENOENT;
  // ENOENT means no file and directory

  ret = strtol(val, &endptr, 10);
  // make into base 10 and store the data at &endptr
  if (val == endptr || *endptr != '\0')
    bail("unable to parse %s=%s", name, val);
  /*
   * Sanity check: this must be a non-negative number.
   */
  if (ret < 0) bail("bad value for %s=%s (%d)", name, val, ret);

  return ret;
}



static void nl_parse(int fd, struct nlconfig_t *config) {
  size_t len, size;
  struct nlmsghdr hdr;
  char *current, *data;

  /* Retrieve the netlink header. */
  len = read(fd, &hdr, NLMSG_HDRLEN);
  if (len != NLMSG_HDRLEN) bail("invalid netlink header length %zu", len);

  /* Retrieve data. */
  size = NLMSG_PAYLOAD(&hdr, 0);
  data = (char *)malloc(size);
  current = data;

  if (!data)
    bail("failed to allocate %zu bytes of memory for nl_payload", size);

  len = read(fd, data, size);
  if (len != size)
    bail("failed to read netlink payload, %zu != %zu", len, size);

  /* Parse the netlink payload. */
  config->data = data;
  while (current < data + size) {
    struct nlattr *nlattr = (struct nlattr *)current;
    size_t payload_len = nlattr->nla_len - NLA_HDRLEN;

    /* Advance to payload. */
    current += NLA_HDRLEN;

    /* Handle payload. */
    switch (nlattr->nla_type) {
      case CLONE_FLAGS_ATTR:
        config->cloneflags = readint32(current);
        break;

      default:
        bail("unknown netlink message type %d", nlattr->nla_type);
    }

    current += NLA_ALIGN(payload_len);
  }
}

void nl_free(struct nlconfig_t *config) { free(config->data); }

// nsenter.go call nsexec function for creating containers.
void nsexec(void) {
  	int pipenum;
	jmp_buf env;
	int sync_child_pipe[2], sync_grandchild_pipe[2];
	struct nlconfig_t config = { 0 };

	setup_logpipe();

	pipenum = getenv_int("_LIBCONTAINER_INITPIPE");
	if (pipenum < 0) {
		/* We are not a runc init. Just return to go runtime. */
		return;
	}



	if (write(pipenum, "", 1) != 1)
		bail("could not inform the parent we are past initial setup");

	
	write_log(DEBUG, "=> nsexec container setup");


	/* Parse all of the netlink configuration. */
	nl_parse(pipenum, &config);

	/* Pipe so we can tell the child when we've finished setting up. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_child_pipe) < 0)
		bail("failed to setup sync pipe between parent and child");

	/*
	 * We need a new socketpair to sync with grandchild so we don't have
	 * race condition with child.
	 */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_grandchild_pipe) < 0)
		bail("failed to setup sync pipe between parent and grandchild");

	switch (setjmp(env)) {
	case STAGE_PARENT:{
			int len;
			pid_t stage1_pid = -1, stage2_pid = -1;
			bool stage1_complete, stage2_complete;

			/* For debugging. */
			current_stage = STAGE_PARENT;
			prctl(PR_SET_NAME, (unsigned long)"runc:[0:PARENT]", 0, 0, 0);
			write_log(DEBUG, "~> nsexec stage-0");

			/* Start the process of getting a container. */
			write_log(DEBUG, "spawn stage-1");
			stage1_pid = clone_parent(&env, STAGE_CHILD);
			if (stage1_pid < 0)
				bail("unable to spawn stage-1");

			syncfd = sync_child_pipe[1];
			if (close(sync_child_pipe[0]) < 0)
				bail("failed to close sync_child_pipe[0] fd");

			/*
			 * State machine for synchronisation with the children. We only
			 * return once both the child and grandchild are ready.
			 */
			write_log(DEBUG, "-> stage-1 synchronisation loop");
			stage1_complete = false;
			while (!stage1_complete) {
				enum sync_t s;

				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with stage-1: next state");

				switch (s) {
				case SYNC_USERMAP_PLS:
					write_log(DEBUG, "stage-1 requested userns mappings");

					/*
					 * Enable setgroups(2) if we've been asked to. But we also
					 * have to explicitly disable setgroups(2) if we're
					 * creating a rootless container for single-entry mapping.
					 * i.e. config.is_setgroup == false.
					 * (this is required since Linux 3.19).
					 *
					 * For rootless multi-entry mapping, config.is_setgroup shall be true and
					 * newuidmap/newgidmap shall be used.
					 */
					if (config.is_rootless_euid && !config.is_setgroup)
						update_setgroups(stage1_pid, SETGROUPS_DENY);

					/* Set up mappings. */
					update_uidmap(config.uidmappath, stage1_pid, config.uidmap, config.uidmap_len);
					update_gidmap(config.gidmappath, stage1_pid, config.gidmap, config.gidmap_len);

					s = SYNC_USERMAP_ACK;
					if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
						sane_kill(stage1_pid, SIGKILL);
						sane_kill(stage2_pid, SIGKILL);
						bail("failed to sync with stage-1: write(SYNC_USERMAP_ACK)");
					}
					break;
				case SYNC_RECVPID_PLS:
					write_log(DEBUG, "stage-1 requested pid to be forwarded");

					/* Get the stage-2 pid. */
					if (read(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
						sane_kill(stage1_pid, SIGKILL);
						bail("failed to sync with stage-1: read(stage2_pid)");
					}

					/* Send ACK. */
					s = SYNC_RECVPID_ACK;
					if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
						sane_kill(stage1_pid, SIGKILL);
						sane_kill(stage2_pid, SIGKILL);
						bail("failed to sync with stage-1: write(SYNC_RECVPID_ACK)");
					}

					/*
					 * Send both the stage-1 and stage-2 pids back to runc.
					 * runc needs the stage-2 to continue process management,
					 * but because stage-1 was spawned with CLONE_PARENT we
					 * cannot reap it within stage-0 and thus we need to ask
					 * runc to reap the zombie for us.
					 */
					write_log(DEBUG, "forward stage-1 (%d) and stage-2 (%d) pids to runc",
						  stage1_pid, stage2_pid);
					len =
					    dprintf(pipenum, "{\"stage1_pid\":%d,\"stage2_pid\":%d}\n", stage1_pid,
						    stage2_pid);
					if (len < 0) {
						sane_kill(stage1_pid, SIGKILL);
						sane_kill(stage2_pid, SIGKILL);
						bail("failed to sync with runc: write(pid-JSON)");
					}
					break;
				case SYNC_MOUNTSOURCES_PLS:
					write_log(DEBUG, "stage-1 requested to open mount sources");
					send_mountsources(syncfd, stage1_pid, config.mountsources,
							  config.mountsources_len);

					s = SYNC_MOUNTSOURCES_ACK;
					if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
						sane_kill(stage1_pid, SIGKILL);
						bail("failed to sync with child: write(SYNC_MOUNTSOURCES_ACK)");
					}
					break;
				case SYNC_CHILD_FINISH:
					write_log(DEBUG, "stage-1 complete");
					stage1_complete = true;
					break;
				default:
					bail("unexpected sync value: %u", s);
				}
			}
			write_log(DEBUG, "<- stage-1 synchronisation loop");

			/* Now sync with grandchild. */
			syncfd = sync_grandchild_pipe[1];
			if (close(sync_grandchild_pipe[0]) < 0)
				bail("failed to close sync_grandchild_pipe[0] fd");

			write_log(DEBUG, "-> stage-2 synchronisation loop");
			stage2_complete = false;
			while (!stage2_complete) {
				enum sync_t s;

				write_log(DEBUG, "signalling stage-2 to run");
				s = SYNC_GRANDCHILD;
				if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
					sane_kill(stage2_pid, SIGKILL);
					bail("failed to sync with child: write(SYNC_GRANDCHILD)");
				}

				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with child: next state");

				switch (s) {
				case SYNC_CHILD_FINISH:
					write_log(DEBUG, "stage-2 complete");
					stage2_complete = true;
					break;
				default:
					bail("unexpected sync value: %u", s);
				}
			}
			write_log(DEBUG, "<- stage-2 synchronisation loop");
			write_log(DEBUG, "<~ nsexec stage-0");
			exit(0);
		}
		break;
	case STAGE_CHILD:{
			pid_t stage2_pid = -1;
			enum sync_t s;

			current_stage = STAGE_CHILD;

			/* We're in a child and thus need to tell the parent if we die. */
			syncfd = sync_child_pipe[0];
			if (close(sync_child_pipe[1]) < 0)
				bail("failed to close sync_child_pipe[1] fd");
			
			prctl(PR_SET_NAME, (unsigned long)"runc:[1:CHILD]", 0, 0, 0);
			write_log(DEBUG, "~> nsexec stage-1");

			if (config.cloneflags & CLONE_NEWUSER) {
				s = SYNC_USERMAP_PLS;
				if (write(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: write(SYNC_USERMAP_PLS)");

				/* ... wait for mapping ... */
				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: read(SYNC_USERMAP_ACK)");
				if (s != SYNC_USERMAP_ACK)
					bail("failed to sync with parent: SYNC_USERMAP_ACK: got %u", s);

				
			}

			stage2_pid = clone_parent(&env, STAGE_INIT);
			if (stage2_pid < 0)
				bail("unable to spawn stage-2");

			/* Send the child to our parent, which knows what it's doing. */
			s = SYNC_RECVPID_PLS;
			if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(SYNC_RECVPID_PLS)");
			}
			if (write(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(stage2_pid)");
			}
			
			write_log(DEBUG, "request stage-0 to map user namespace");

			/* ... wait for parent to get the pid ... */
			if (read(syncfd, &s, sizeof(s)) != sizeof(s)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: read(SYNC_RECVPID_ACK)");
			}
			if (s != SYNC_RECVPID_ACK) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: SYNC_RECVPID_ACK: got %u", s);
				
			}

			write_log(DEBUG, "signal completion to stage-0");

			s = SYNC_CHILD_FINISH;
			if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(SYNC_CHILD_FINISH)");
			}
			/* Our work is done. [Stage 2: STAGE_INIT] is doing the rest of the work. */
			write_log(DEBUG, "<~ nsexec stage-1");
			exit(0);
		}
		break;
	case STAGE_INIT:{
			/*
			 * We're inside the child now, having jumped from the
			 * start_child() code after forking in the parent.
			 */
			enum sync_t s;

			/* For debugging. */
			current_stage = STAGE_INIT;

			/* We're in a child and thus need to tell the parent if we die. */
			syncfd = sync_grandchild_pipe[0];
			if (close(sync_grandchild_pipe[1]) < 0)
				bail("failed to close sync_grandchild_pipe[1] fd");

			if (close(sync_child_pipe[0]) < 0)
				bail("failed to close sync_child_pipe[0] fd");

			if (read(syncfd, &s, sizeof(s)) != sizeof(s))
				bail("failed to sync with parent: read(SYNC_GRANDCHILD)");
			if (s != SYNC_GRANDCHILD)
				bail("failed to sync with parent: SYNC_GRANDCHILD: got %u", s);

			if (setsid() < 0)
				bail("setsid failed");

			if (setuid(0) < 0)
				bail("setuid failed");

			if (setgid(0) < 0)
				bail("setgid failed");

			write_log(DEBUG, "signal completion to stage-0");
			s = SYNC_CHILD_FINISH;
			if (write(syncfd, &s, sizeof(s)) != sizeof(s))
				bail("failed to sync with parent: write(SYNC_CHILD_FINISH)");

			/* Close sync pipes. */
			if (close(sync_grandchild_pipe[0]) < 0)
				bail("failed to close sync_grandchild_pipe[0] fd");

			/* Free netlink data. */
			nl_free(&config);

			/* Finish executing, let the Go runtime take over. */
			write_log(DEBUG, "<= nsexec container setup");
			write_log(DEBUG, "booting up go runtime ...");
			return;
		}
		break;
	default:
		bail("unexpected jump value");
	}
}