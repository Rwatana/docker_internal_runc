void nsexec(void)
{
	int pipenum;
	jmp_buf env;
	int sync_child_pipe[2], sync_grandchild_pipe[2];
	struct nlconfig_t config = { 0 };

	/*
	 * Setup a pipe to send logs to the parent. This should happen
	 * first, because bail will use that pipe.
	 */
	setup_logpipe();

	/*
	 * Get the init pipe fd from the environment. The init pipe is used to
	 * read the bootstrap data and tell the parent what the new pids are
	 * after the setup is done.
	 */
	pipenum = getenv_int("_LIBCONTAINER_INITPIPE");
	if (pipenum < 0) {
		/* We are not a runc init. Just return to go runtime. */
		return;
	}

	/*
	 * We need to re-exec if we are not in a cloned binary. This is necessary
	 * to ensure that containers won't be able to access the host binary
	 * through /proc/self/exe. See CVE-2019-5736.
	 */
	if (ensure_cloned_binary() < 0)
		bail("could not ensure we are a cloned binary");

	/*
	 * Inform the parent we're past initial setup.
	 * For the other side of this, see initWaiter.
	 */
	if (write(pipenum, "", 1) != 1)
		bail("could not inform the parent we are past initial setup");

	write_log(DEBUG, "=> nsexec container setup");

	/* Parse all of the netlink configuration. */
	nl_parse(pipenum, &config);

	/* Set oom_score_adj. This has to be done before !dumpable because
	 * /proc/self/oom_score_adj is not writeable unless you're an privileged
	 * user (if !dumpable is set). All children inherit their parent's
	 * oom_score_adj value on fork(2) so this will always be propagated
	 * properly.
	 */
	update_oom_score_adj(config.oom_score_adj, config.oom_score_adj_len);

	/*
	 * Make the process non-dumpable, to avoid various race conditions that
	 * could cause processes in namespaces we're joining to access host
	 * resources (or potentially execute code).
	 *
	 * However, if the number of namespaces we are joining is 0, we are not
	 * going to be switching to a different security context. Thus setting
	 * ourselves to be non-dumpable only breaks things (like rootless
	 * containers), which is the recommendation from the kernel folks.
	 */
	if (config.namespaces) {
		write_log(DEBUG, "set process as non-dumpable");
		if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
			bail("failed to set process as non-dumpable");
	}

	/* Pipe so we can tell the child when we've finished setting up. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_child_pipe) < 0)
		bail("failed to setup sync pipe between parent and child");

	/*
	 * We need a new socketpair to sync with grandchild so we don't have
	 * race condition with child.
	 */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_grandchild_pipe) < 0)
		bail("failed to setup sync pipe between parent and grandchild");

	/* TODO: Currently we aren't dealing with child deaths properly. */

	/*
	 * Okay, so this is quite annoying.
	 *
	 * In order for this unsharing code to be more extensible we need to split
	 * up unshare(CLONE_NEWUSER) and clone() in various ways. The ideal case
	 * would be if we did clone(CLONE_NEWUSER) and the other namespaces
	 * separately, but because of SELinux issues we cannot really do that. But
	 * we cannot just dump the namespace flags into clone(...) because several
	 * usecases (such as rootless containers) require more granularity around
	 * the namespace setup. In addition, some older kernels had issues where
	 * CLONE_NEWUSER wasn't handled before other namespaces (but we cannot
	 * handle this while also dealing with SELinux so we choose SELinux support
	 * over broken kernel support).
	 *
	 * However, if we unshare(2) the user namespace *before* we clone(2), then
	 * all hell breaks loose.
	 *
	 * The parent no longer has permissions to do many things (unshare(2) drops
	 * all capabilities in your old namespace), and the container cannot be set
	 * up to have more than one {uid,gid} mapping. This is obviously less than
	 * ideal. In order to fix this, we have to first clone(2) and then unshare.
	 *
	 * Unfortunately, it's not as simple as that. We have to fork to enter the
	 * PID namespace (the PID namespace only applies to children). Since we'll
	 * have to double-fork, this clone_parent() call won't be able to get the
	 * PID of the _actual_ init process (without doing more synchronisation than
	 * I can deal with at the moment). So we'll just get the parent to send it
	 * for us, the only job of this process is to update
	 * /proc/pid/{setgroups,uid_map,gid_map}.
	 *
	 * And as a result of the above, we also need to setns(2) in the first child
	 * because if we join a PID namespace in the topmost parent then our child
	 * will be in that namespace (and it will not be able to give us a PID value
	 * that makes sense without resorting to sending things with cmsg).
	 *
	 * This also deals with an older issue caused by dumping cloneflags into
	 * clone(2): On old kernels, CLONE_PARENT didn't work with CLONE_NEWPID, so
	 * we have to unshare(2) before clone(2) in order to do this. This was fixed
	 * in upstream commit 1f7f4dde5c945f41a7abc2285be43d918029ecc5, and was
	 * introduced by 40a0d32d1eaffe6aac7324ca92604b6b3977eb0e. As far as we're
	 * aware, the last mainline kernel which had this bug was Linux 3.12.
	 * However, we cannot comment on which kernels the broken patch was
	 * backported to.
	 *
	 * -- Aleksa "what has my life come to?" Sarai
	 */

	switch (setjmp(env)) {
		/*
		 * Stage 0: We're in the parent. Our job is just to create a new child
		 *          (stage 1: STAGE_CHILD) process and write its uid_map and
		 *          gid_map. That process will go on to create a new process, then
		 *          it will send us its PID which we will send to the bootstrap
		 *          process.
		 */
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

		/*
		 * Stage 1: We're in the first child process. Our job is to join any
		 *          provided namespaces in the netlink payload and unshare all of
		 *          the requested namespaces. If we've been asked to CLONE_NEWUSER,
		 *          we will ask our parent (stage 0) to set up our user mappings
		 *          for us. Then, we create a new child (stage 2: STAGE_INIT) for
		 *          PID namespace. We then send the child's PID to our parent
		 *          (stage 0).
		 */
	case STAGE_CHILD:{
			pid_t stage2_pid = -1;
			enum sync_t s;

			/* For debugging. */
			current_stage = STAGE_CHILD;

			/* We're in a child and thus need to tell the parent if we die. */
			syncfd = sync_child_pipe[0];
			if (close(sync_child_pipe[1]) < 0)
				bail("failed to close sync_child_pipe[1] fd");

			/* For debugging. */
			prctl(PR_SET_NAME, (unsigned long)"runc:[1:CHILD]", 0, 0, 0);
			write_log(DEBUG, "~> nsexec stage-1");

			/*
			 * We need to setns first. We cannot do this earlier (in stage 0)
			 * because of the fact that we forked to get here (the PID of
			 * [stage 2: STAGE_INIT]) would be meaningless). We could send it
			 * using cmsg(3) but that's just annoying.
			 */
			if (config.namespaces)
				join_namespaces(config.namespaces);

			/*
			 * Deal with user namespaces first. They are quite special, as they
			 * affect our ability to unshare other namespaces and are used as
			 * context for privilege checks.
			 *
			 * We don't unshare all namespaces in one go. The reason for this
			 * is that, while the kernel documentation may claim otherwise,
			 * there are certain cases where unsharing all namespaces at once
			 * will result in namespace objects being owned incorrectly.
			 * Ideally we should just fix these kernel bugs, but it's better to
			 * be safe than sorry, and fix them separately.
			 *
			 * A specific case of this is that the SELinux label of the
			 * internal kern-mount that mqueue uses will be incorrect if the
			 * UTS namespace is cloned before the USER namespace is mapped.
			 * I've also heard of similar problems with the network namespace
			 * in some scenarios. This also mirrors how LXC deals with this
			 * problem.
			 */
			if (config.cloneflags & CLONE_NEWUSER) {
				try_unshare(CLONE_NEWUSER, "user namespace");
				config.cloneflags &= ~CLONE_NEWUSER;

				/*
				 * We need to set ourselves as dumpable temporarily so that the
				 * parent process can write to our procfs files.
				 */
				if (config.namespaces) {
					write_log(DEBUG, "temporarily set process as dumpable");
					if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
						bail("failed to temporarily set process as dumpable");
				}

				/*
				 * We don't have the privileges to do any mapping here (see the
				 * clone_parent rant). So signal stage-0 to do the mapping for
				 * us.
				 */
				write_log(DEBUG, "request stage-0 to map user namespace");
				s = SYNC_USERMAP_PLS;
				if (write(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: write(SYNC_USERMAP_PLS)");

				/* ... wait for mapping ... */
				write_log(DEBUG, "request stage-0 to map user namespace");
				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: read(SYNC_USERMAP_ACK)");
				if (s != SYNC_USERMAP_ACK)
					bail("failed to sync with parent: SYNC_USERMAP_ACK: got %u", s);

				/* Revert temporary re-dumpable setting. */
				if (config.namespaces) {
					write_log(DEBUG, "re-set process as non-dumpable");
					if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
						bail("failed to re-set process as non-dumpable");
				}

				/* Become root in the namespace proper. */
				if (setresuid(0, 0, 0) < 0)
					bail("failed to become root in user namespace");
			}

			/*
			 * Unshare all of the namespaces. Now, it should be noted that this
			 * ordering might break in the future (especially with rootless
			 * containers). But for now, it's not possible to split this into
			 * CLONE_NEWUSER + [the rest] because of some RHEL SELinux issues.
			 *
			 * Note that we don't merge this with clone() because there were
			 * some old kernel versions where clone(CLONE_PARENT | CLONE_NEWPID)
			 * was broken, so we'll just do it the long way anyway.
			 */
			try_unshare(config.cloneflags & ~CLONE_NEWCGROUP, "remaining namespaces (except cgroupns)");

			/* Ask our parent to send the mount sources fds. */
			if (config.mountsources) {
				write_log(DEBUG, "request stage-0 to send mount sources");
				s = SYNC_MOUNTSOURCES_PLS;
				if (write(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: write(SYNC_MOUNTSOURCES_PLS)");

				/* Receive and install all mount sources fds. */
				receive_mountsources(syncfd);

				/* Parent finished to send the mount sources fds. */
				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: read(SYNC_MOUNTSOURCES_ACK)");
				if (s != SYNC_MOUNTSOURCES_ACK)
					bail("failed to sync with parent: SYNC_MOUNTSOURCES_ACK: got %u", s);
			}

			/*
			 * TODO: What about non-namespace clone flags that we're dropping here?
			 *
			 * We fork again because of PID namespace, setns(2) or unshare(2) don't
			 * change the PID namespace of the calling process, because doing so
			 * would change the caller's idea of its own PID (as reported by getpid()),
			 * which would break many applications and libraries, so we must fork
			 * to actually enter the new PID namespace.
			 */
			write_log(DEBUG, "spawn stage-2");
			stage2_pid = clone_parent(&env, STAGE_INIT);
			if (stage2_pid < 0)
				bail("unable to spawn stage-2");

			/* Send the child to our parent, which knows what it's doing. */
			write_log(DEBUG, "request stage-0 to forward stage-2 pid (%d)", stage2_pid);
			s = SYNC_RECVPID_PLS;
			if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(SYNC_RECVPID_PLS)");
			}
			if (write(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(stage2_pid)");
			}

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

		/*
		 * Stage 2: We're the final child process, and the only process that will
		 *          actually return to the Go runtime. Our job is to just do the
		 *          final cleanup steps and then return to the Go runtime to allow
		 *          init_linux.go to run.
		 */
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

			/* For debugging. */
			prctl(PR_SET_NAME, (unsigned long)"runc:[2:INIT]", 0, 0, 0);
			write_log(DEBUG, "~> nsexec stage-2");

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

			if (!config.is_rootless_euid && config.is_setgroup) {
				if (setgroups(0, NULL) < 0)
					bail("setgroups failed");
			}

			if (config.cloneflags & CLONE_NEWCGROUP) {
				try_unshare(CLONE_NEWCGROUP, "cgroup namespace");
			}

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

	/* Should never be reached. */
	bail("should never be reached");
}