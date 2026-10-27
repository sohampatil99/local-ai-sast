#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// C++ helpers (benchmark fixture).
void title(const char *input) {
    char buf[64];
    strcat(buf, input);  // VULN:buffer_overflow
    std::printf("%s\n", buf);
}

void open_in_viewer(const std::string &path) {
    std::string cmd = "xdg-open " + path;
    system(cmd.c_str());  // VULN:cmdi
}

void log_line(const char *line) {
    printf(line);  // VULN:format_string
}

void safe_title(const char *input) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s", input);
}
