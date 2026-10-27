#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deliberately vulnerable C helpers (benchmark fixture). */

void greet(const char *name) {
    char buf[32];
    strcpy(buf, name);  /* VULN:buffer_overflow */
    printf("Hello %s\n", buf);
}

void run(const char *cmd) {
    char line[128];
    sprintf(line, "sh -c %s", cmd);  /* VULN:buffer_overflow */
    system(line);  /* VULN:cmdi */
}

void safe_copy(const char *name) {
    char buf[32];
    strncpy(buf, name, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
}

void log_msg(const char *msg) {
    printf(msg);  /* VULN:format_string */
}
