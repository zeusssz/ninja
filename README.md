## Raven - Vulnerability Detection Tool

Raven is a high-performance vulnerability detection tool written in C++. It integrates with the Z3 Theorem Prover for symbolic execution and cURL for fetching vulnerability data from APIs like the National Vulnerability Database (NVD).

---

### Features

- **Static Analysis**:
  - Detects memory leaks, buffer overflows, SQL injection, XSS, and CSRF vulnerabilities.
  
- **Dynamic Analysis**:
  - Monitors for runtime errors and resource leaks.

- **API Integration**:
  - Fetches real-time vulnerability data from trusted sources like NVD.

---

### Table of Contents

1. [Installation](#installation)
2. [Usage](#usage)
3. [Configuration](#configuration)
4. [API Integration](#api-integration)
5. [Development](#development)
6. [License](#license)

---

### Installation

Before using Raven, you need to install several dependencies. Follow these steps to set up your environment.

#### Dependencies

1. **Z3 Theorem Prover**
   - **Installation**:
     ```bash
     sudo apt-get install z3
     ```
   - Alternatively, you can [download and install Z3 from GitHub](https://github.com/Z3Prover/z3).

>[!NOTE]  
   Make sure Z3 is properly installed and accessible in your system's `PATH`.

2. **cURL Library**
   - **Installation**:
     ```bash
     sudo apt-get install libcurl4-openssl-dev
     ```

3. **JSON for Modern C++ (nlohmann/json)**
   - **Installation**:
     Add this to your `CMakeLists.txt`:
     ```cmake
     include(FetchContent)
     FetchContent_Declare(
       json
       GIT_REPOSITORY https://github.com/nlohmann/json.git
       GIT_TAG v3.9.1
     )
     FetchContent_MakeAvailable(json)
     target_link_libraries(Raven PRIVATE nlohmann_json::nlohmann_json)
     ```

4. **CMake**
   - **Installation**:
     ```bash
     sudo apt-get install cmake
     ```

#### Full Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/zeusssz/raven.git
   cd raven
   ```

2. Build the project:
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```

>[!WARNING]  
> Ensure that Z3 and cURL are correctly installed and configured. Missing dependencies will result in build failure.

---

### Usage

Once Raven is installed, you can run the application by executing the following command in the build directory:

```bash
./Raven
```

You can specify options like file paths or APIs for vulnerability detection:

```bash
./Raven --file <source-code-path> --api <nvd-api-url>
```

>[!INFORMATION]  
> By default, Raven performs static analysis. You can extend it to dynamic analysis by using the `--dynamic` flag.

---

### Configuration

To configure Raven for different vulnerability databases, update the configuration file at `config.json`.

#### Example Configuration:

```json
{
  "api_url": "https://services.nvd.nist.gov/rest/json/cves/1.0",
  "api_key": "your_api_key_here"
}
```

>[!NOTE]  
> Make sure to keep your API keys secure and avoid committing them to public repositories.

---

### API Integration

Raven fetches real-time vulnerability data using the **cURL** library. By default, it integrates with the National Vulnerability Database (NVD).

#### NVD Integration

1. Ensure you have an NVD API key.
2. Update the `config.json` file with your API URL and key.
3. Run Raven to fetch and analyze the latest vulnerabilities.

>[!WARNING]  
> Excessive API requests might result in rate limiting. Use caching mechanisms or avoid frequent calls in production environments.

---

### Development

Feel free to contribute to Raven. Before submitting a pull request, ensure that:

- Your code follows the project’s coding standards.
- The project builds and runs correctly with no errors.
- You write tests for any new functionality.

---

### License

Raven is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
