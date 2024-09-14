#include "analysis.h"
#include "api_client.h"
#include "utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <code_file>" << std::endl;
        return 1;
    }

    std::ifstream codeFile(argv[1]);
    if (!codeFile.is_open()) {
        logError("Error: Unable to open file " + std::string(argv[1]));
        return 1;
    }

    std::stringstream buffer;
    buffer << codeFile.rdbuf();
    std::string code = buffer.str();

    try {
        auto config = loadConfig("config.json");
        auto nvdData = fetchVulnerabilityData(config["nvd_url"]);
        auto vulnDBData = fetchVulnerabilityData(config["vulndb_url"]);

        auto nvdSignatures = parseVulnerabilityData(nvdData);
        auto vulnDBSignatures = parseVulnerabilityData(vulnDBData);

        std::vector<std::string> allSignatures;
        allSignatures.insert(allSignatures.end(), nvdSignatures.begin(), nvdSignatures.end());
        allSignatures.insert(allSignatures.end(), vulnDBSignatures.begin(), vulnDBSignatures.end());

        auto staticVulns = staticAnalysis(code);
        auto signatureVulns = checkSignatures(code, allSignatures);

        std::cout << "Static Analysis Results:\n";
        for (const auto& vuln : staticVulns) {
            std::cout << "  - " << vuln << "\n";
        }

        std::cout << "Signature-Based Detection Results:\n";
        for (const auto& vuln : signatureVulns) {
            std::cout << "  - " << vuln << "\n";
        }

        dynamicAnalysis(code);
        analyzeWithZ3(code);

    } catch (const std::exception& e) {
        logError("Error during analysis: " + std::string(e.what()));
        return 1;
    }

    return 0;
}
