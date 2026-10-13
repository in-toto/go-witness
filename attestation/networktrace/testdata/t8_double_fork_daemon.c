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

#include "test_helpers.h"
#include <errno.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;

    pid_t first = fork();
    if (first < 0) return 3;
    if (first > 0) _exit(0);

    if (setsid() < 0) _exit(4);

    pid_t second = fork();
    if (second < 0) _exit(5);
    if (second > 0) _exit(0);

    usleep(300000);
    _exit(send_traffic(argv[1], "DAEMON") == 0 ? 0 : 6);
}
