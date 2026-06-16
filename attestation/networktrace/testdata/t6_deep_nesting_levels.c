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

// T6: 3-level nesting with CLONE_NEWNET at the deepest level.
//
// Level 1: CLONE_NEWPID, same netns (fork handler marks PID ns)
// Level 2: CLONE_NEWPID, same netns (fork handler sees parent's PID ns is
//          tracked, marks grandchild PID ns — transitive propagation)
// Level 3: CLONE_NEWPID + CLONE_NEWNET (gate freezes, sweep injects proxy,
//          SIGCONT using numbers[witness_level].nr at depth 3)
//
// If witness_pid_ns_level_map was not populated or the direct index is wrong,
// SendSIGCONT targets an incorrect PID → kill() fails → watchdog → fail-closed.

#include "test_helpers.h"

static int level3_fn(void *arg) {
    char *port = (char *)arg;
    bring_up_loopback();
    send_traffic(port, "DEEP");
    return 0;
}

static int level2_fn(void *arg) {
    char *port = (char *)arg;
    char *stack = malloc(STACK_SIZE);
    if (!stack) return 1;
    pid_t pid = clone(level3_fn, stack + STACK_SIZE,
                      CLONE_NEWPID | CLONE_NEWNET | SIGCHLD, port);
    if (pid < 0) {
        perror("clone l3");
        free(stack);
        return 1;
    }
    waitpid(pid, NULL, 0);
    free(stack);
    return 0;
}

static int level1_fn(void *arg) {
    char *port = (char *)arg;
    char *stack = malloc(STACK_SIZE);
    if (!stack) return 1;
    pid_t pid = clone(level2_fn, stack + STACK_SIZE,
                      CLONE_NEWPID | SIGCHLD, port);
    if (pid < 0) {
        perror("clone l2");
        free(stack);
        return 1;
    }
    waitpid(pid, NULL, 0);
    free(stack);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    char *port = argv[1];
    char *stack = malloc(STACK_SIZE);
    if (!stack) return 1;
    pid_t pid = clone(level1_fn, stack + STACK_SIZE,
                      CLONE_NEWPID | SIGCHLD, port);
    if (pid < 0) {
        perror("clone l1");
        free(stack);
        return 1;
    }
    waitpid(pid, NULL, 0);
    free(stack);
    return 0;
}
