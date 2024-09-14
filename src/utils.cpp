#include "utils.h"
#include <fstream>

void logError(const std::string& message) {
    std::ofstream logFile("raven.log", std::ios_base::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
    }
}
