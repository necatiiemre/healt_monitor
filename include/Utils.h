#pragma once

#include <iosfwd>   // std::ostream
#include <string>
#include <unistd.h>
#include <iostream>
#include <limits>
#include <csignal>


namespace utils {

    // Set float format for global stream (e.g., std::cout)
    void set_global_float_format(std::ostream& os = std::cout,
                                 int precision = 2,
                                 bool fixed = true);

    // Reset global stream format to reasonable default
    void reset_float_format(std::ostream& os = std::cout);

    // Generate formatted string from a number
    std::string format_float(double value,
                             int precision = 2,
                             bool fixed = true);

    void pressEnterForDebug();

    // Ctrl+C (SIGINT) sinyali gelene kadar bekler, sonra kod devam eder
    void waitForCtrlC();

    // RAII guard to change format only within a specific scope
    class FloatFormatGuard {
    public:
        FloatFormatGuard(std::ostream& os,
                         int precision,
                         bool fixed = true);

        ~FloatFormatGuard();

    private:
        std::ostream&      m_os;
        std::ios::fmtflags m_old_flags;
        std::streamsize    m_old_precision;
    };

} // namespace utils
