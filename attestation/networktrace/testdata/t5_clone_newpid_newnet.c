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


// Clone into a new PID namespace and a new network namespace. The child
// brings up loopback and sends traffic. The namespace gate must freeze the
// child, the sweep loop must inject a proxy via setns into the new netns,
// mark it ready, and SIGCONT the child. This also does not do execve() to
// change the executing code, same currently being executed program does the
// namespace transition. While docker does not most likely do this (it uses execve() to load
// users program), but still hooking at namespace gate mitigates this.

#include "test_helpers.h"

static int child_fn(void *arg) {
    char *port = (char *)arg;
    bring_up_loopback();
    send_traffic(port, "DOCKER");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    char *port = argv[1];
    char *stack = malloc(STACK_SIZE);
    if (!stack) return 1;
    pid_t pid = clone(child_fn, stack + STACK_SIZE,
                      CLONE_NEWPID | CLONE_NEWNET | SIGCHLD, port);
    if (pid < 0) {
        perror("clone");
        free(stack);
        return 1;
    }
    waitpid(pid, NULL, 0);
    free(stack);
    return 0;
}
