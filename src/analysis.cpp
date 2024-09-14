#include "analysis.h"
#include "utils.h"
#include <z3++.h>

std::vector<std::string> staticAnalysis(const std::string& code) {
    std::vector<std::string> vulnerabilities;

    if (code.find("SELECT") != std::string::npos) {
        vulnerabilities.push_back("Possible SQL Injection detected.");
    }
    if (code.find("fopen") != std::string::npos && code.find("w") != std::string::npos) {
        vulnerabilities.push_back("Potential file write vulnerability detected.");
    }
    if (code.find("exec") != std::string::npos) {
        vulnerabilities.push_back("Potential command execution vulnerability detected.");
    }
    if (code.find("eval") != std::string::npos) {
        vulnerabilities.push_back("Potential code injection vulnerability detected.");
    }
    if (code.find("strcpy") != std::string::npos) {
        vulnerabilities.push_back("Potential buffer overflow vulnerability detected.");
    }

    return vulnerabilities;
}

void dynamicAnalysis(const std::string& code) {
    try {
        if (code.find("runtime_error") != std::string::npos) {
            throw std::runtime_error("Simulated runtime error.");
        }
    } catch (const std::exception& e) {
        logError("Runtime error: " + std::string(e.what()));
    }
}

void analyzeWithZ3(const std::string& code) {
    z3::context c;
    z3::solver s(c);

    z3::expr buffer_size = z3::int_const("buffer_size", c);
    z3::expr data_size = z3::int_const("data_size", c);

    s.add(buffer_size >= data_size);

    if (code.find("strcpy") != std::string::npos) {
        s.add(buffer_size < data_size);
    }

    switch (s.check()) {
        case z3::sat:
            std::cout << "Z3 analysis: Constraints are satisfiable, potential vulnerability detected." << std::endl;
            break;
        case z3::unsat:
            std::cout << "Z3 analysis: Constraints are unsatisfiable, no vulnerability detected." << std::endl;
            break;
        case z3::unknown:
            std::cout << "Z3 analysis: Result is unknown, further investigation required." << std::endl;
            break;
    }
}
