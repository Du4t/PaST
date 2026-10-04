#ifndef SOURCE_LOCATION_H
#define SOURCE_LOCATION_H

#include <string>

struct SourceLocation {
    std::string file;
    unsigned line;
    std::string function;

    SourceLocation() : line(0) {}
    SourceLocation(const std::string &f, unsigned l, const std::string &fn)
        : file(f), line(l), function(fn) {}
};

#endif
