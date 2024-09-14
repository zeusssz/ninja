#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <string>
#include <vector>

std::vector<std::string> staticAnalysis(const std::string& code);
void dynamicAnalysis(const std::string& code);
void analyzeWithZ3(const std::string& code);

#endif // ANALYSIS_H
