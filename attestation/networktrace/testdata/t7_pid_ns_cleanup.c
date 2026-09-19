// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// T7: tracked_pid_ns_map cleanup on container init exit.
//
// Create two sequential containers (CLONE_NEWPID, same netns). When the first
// container's init (PID 1) exits, sched_process_exit must delete its PID ns
// from tracked_pid_ns_map. The second container gets a new PID ns inode and
// must be tracked independently.

#include "test_helpers.h"

static int child_fn(void *arg) {
    char *port = (char *)arg;
    send_traffic(port, "CLEANUP");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    char *port = argv[1];

    char *stack1 = malloc(STACK_SIZE);
    if (!stack1) return 1;
    pid_t pid1 = clone(child_fn, stack1 + STACK_SIZE,
                       CLONE_NEWPID | SIGCHLD, port);
    if (pid1 < 0) {
        perror("clone1");
        free(stack1);
        return 1;
    }
    waitpid(pid1, NULL, 0);
    free(stack1);

    char *stack2 = malloc(STACK_SIZE);
    if (!stack2) return 1;
    pid_t pid2 = clone(child_fn, stack2 + STACK_SIZE,
                       CLONE_NEWPID | SIGCHLD, port);
    if (pid2 < 0) {
        perror("clone2");
        free(stack2);
        return 1;
    }
    waitpid(pid2, NULL, 0);
    free(stack2);

    return 0;
}
