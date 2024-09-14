#ifndef API_CLIENT_H
#define API_CLIENT_H

#include <string>
#include <vector>

std::string fetchVulnerabilityData(const std::string& url);
std::vector<std::string> parseVulnerabilityData(const std::string& jsonString);

#endif // API_CLIENT_H
