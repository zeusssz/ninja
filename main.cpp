#include <iostream>
#include <curl/curl.h>
#include <z3++.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <string>

using json = nlohmann::json;
using namespace z3;
std::string api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0";
std::string api_key = "your_api_key_here";
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}
std::string fetch_vulnerabilities() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("X-Api-Key: " + api_key).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, api_url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            std::cerr << "cURL Error: " << curl_easy_strerror(res) << std::endl;
        }

        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

void check_buffer_overflow(context& ctx, solver& s, const std::string& cve_id) {
    expr buffer_size = ctx.int_const("buffer_size");
    expr input_size = ctx.int_const("input_size");

    s.add(buffer_size > 0);
    s.add(input_size > 0);
    s.add(input_size > buffer_size);

    if (s.check() == sat) {
        std::cout << "Potential buffer overflow detected for CVE: " << cve_id << "\n";
    } else {
        std::cout << "No buffer overflow detected for CVE: " << cve_id << "\n";
    }
}

void check_integer_overflow(context& ctx, solver& s, const std::string& cve_id) {
    expr x = ctx.int_const("x");
    expr y = ctx.int_const("y");
    expr max_int = ctx.int_val(INT32_MAX);
    
    s.add(x > 0);
    s.add(y > 0);
    s.add(x + y > max_int);
    if (s.check() == sat) {
        std::cout << "Potential integer overflow detected for CVE: " << cve_id << "\n";
    } else {
        std::cout << "No integer overflow detected for CVE: " << cve_id << "\n";
    }
}

void check_sql_injection(context& ctx, solver& s, const std::string& cve_id) {
    expr is_user_input_tainted = ctx.bool_const("is_user_input_tainted");
    expr query_contains_user_input = ctx.bool_const("query_contains_user_input");

    s.add(is_user_input_tainted);
    s.add(query_contains_user_input);

    if (s.check() == sat) {
        std::cout << "Potential SQL Injection detected for CVE: " << cve_id << "\n";
    } else {
        std::cout << "No SQL Injection detected for CVE: " << cve_id << "\n";
    }
}

void check_xss_vulnerability(context& ctx, solver& s, const std::string& cve_id) {
    expr user_input_tainted = ctx.bool_const("user_input_tainted");
    expr script_injected = ctx.bool_const("script_injected");

    s.add(user_input_tainted);
    s.add(script_injected); 
    if (s.check() == sat) {
        std::cout << "Potential XSS vulnerability detected for CVE: " << cve_id << "\n";
    } else {
        std::cout << "No XSS vulnerability detected for CVE: " << cve_id << "\n";
    }
}

void check_csrf_vulnerability(context& ctx, solver& s, const std::string& cve_id) {
    expr session_token_mismatch = ctx.bool_const("session_token_mismatch");
    expr malicious_request_sent = ctx.bool_const("malicious_request_sent");

    s.add(session_token_mismatch);
    s.add(malicious_request_sent);
    if (s.check() == sat) {
        std::cout << "Potential CSRF vulnerability detected for CVE: " << cve_id << "\n";
    } else {
        std::cout << "No CSRF vulnerability detected for CVE: " << cve_id << "\n";
    }
}

void analyze_vulnerabilities(const std::string& vulnerabilities_json) {
    context ctx;
    solver s(ctx);

    json vulnerabilities = json::parse(vulnerabilities_json);
    
    if (vulnerabilities.contains("result")) {
        auto cve_items = vulnerabilities["result"]["CVE_Items"];
        
        for (const auto& item : cve_items) {
            std::string cve_id = item["cve"]["CVE_data_meta"]["ID"];
            std::string description = item["cve"]["description"]["description_data"][0]["value"];

            std::cout << "CVE ID: " << cve_id << "\n";
            std::cout << "Description: " << description << "\n";
            std::cout << "-----------------------------------\n";

            check_buffer_overflow(ctx, s, cve_id);
            check_integer_overflow(ctx, s, cve_id);
            check_sql_injection(ctx, s, cve_id);
            check_xss_vulnerability(ctx, s, cve_id);
            check_csrf_vulnerability(ctx, s, cve_id);
        }
    }
}

int main() {
    std::string vulnerabilities_json = fetch_vulnerabilities();

    if (!vulnerabilities_json.empty()) {
        analyze_vulnerabilities(vulnerabilities_json);
    } else {
        std::cerr << "No vulnerability data retrieved. Exiting.\n";
    }

    return 0;
}
