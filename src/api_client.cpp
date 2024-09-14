#include "api_client.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <stdexcept>

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string fetchVulnerabilityData(const std::string& url) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return readBuffer;
}

std::vector<std::string> parseVulnerabilityData(const std::string& jsonString) {
    std::vector<std::string> signatures;
    auto json = nlohmann::json::parse(jsonString, nullptr, false);

    if (json.is_discarded()) {
        throw std::runtime_error("Failed to parse JSON data");
    }

    for (const auto& item : json["CVE_Items"]) {
        std::string signature = item["cve"]["CVE_data_meta"]["ID"].get<std::string>();
        signatures.push_back(signature);
    }

    return signatures;
}
