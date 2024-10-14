# Proxy Project

## Overview
The Proxy Project is a C++ application that serves as a proxy for TCP and UDP sessions. It includes various filtering capabilities based on IP addresses, ports, protocols, and domains specified in regex format. The application logs statistical information about packet transfers and active sessions every minute.

This project leverages the Boost libraries for asynchronous I/O operations and utilizes `spdlog` for efficient logging. The goal of this project is to provide a flexible and efficient proxy solution that can be easily configured to meet specific requirements.

## Features
- **Proxy TCP and UDP Sessions**: Handles both TCP and UDP traffic.
- **Statistical Logging**: Every minute, logs the following statistics:
  - Number of passed packets
  - Size of passed packets
  - Number of active sessions
  - Number of updated sessions
  - Number of terminated sessions
  - Number of new sessions
  - Number of filtered packets
  - Size of filtered packets
  - Number of sessions for any incoming domains (specified by regex)
  - Size of each of these domains
- **Packet Filtering**: Filters packets based on:
  - IP addresses
  - Ports
  - Any combination of IP and port
  - Domains (using regex)
  - Protocols (HTTP/HTTPS)

## FD.cpp: Find Domain Utility

In addition to its core functionality, the Proxy Project includes a utility file named `FD.cpp`. This component provides functionality to perform DNS lookups and reverse lookups. 

### Key Functions of FD.cpp
- **DNS Lookup**: Takes a domain name as input and retrieves its associated IP addresses using the `dig` command-line tool.
- **Reverse Lookup**: For each retrieved IP address, it performs a reverse lookup to find the corresponding domain names.
- **User Interaction**: The program prompts users for a domain name, processes the input, and displays both the IP addresses and their corresponding domains.

This utility can be useful for network administrators or developers who need to quickly check DNS records while working with the proxy server.

## Requirements
- C++11 or later
- CMake (version 3.0.0 or later)
- Boost libraries (version 1.65.1 or later)
- spdlog library for logging

## Installation

### Clone the Repository
```bash
git clone https://github.com/FarnoodID/Proxy.git
cd Proxy
```
### Build the Project
Run the following commands to build the project:
```bash
mkdir -p program
cd src
mkdir -p build
cd build
cmake ..
make
cp main ../../program
```

## Output Executable
The executable will be located in the ``program`` directory after building.

## Usage
To run the proxy server, use the following command:
```bash
./program/main <config_file>
```
Replace <config_file> with the path to your configuration file.

## Configuration File Structure
The configuration file should include parameters such as:
- ``port``: The port on which the proxy server will listen (default is 1080).
- ``buffer_size``: The size of the buffer for packet processing (default is 8192 bytes).
- ``log_level``: The sensitivity level for logging  (default is 3).
- ``log_every``: Interval for logging statistics (in seconds; default is 60 seconds).
### Example ``connection.conf``:
```text
port 1080
buffer_size 8192
log_level 3
log_every 60
```

## JSON Filter Configuration
The filter settings should be defined in ``filter.json``, specifying IPs, ports, domains, protocols, etc.
### Example ``filter.json``:
```json
{
    "ips": ["192.168.1.1", "10.0.0.1"],
    "ip_ports": ["192.168.1.1:80"],
    "ports": ["80", "443"],
    "domains": ["example\\.com", "test\\.org"],
    "protocols": ["http", "https"]
}
```

## Logging
The application uses ``spdlog`` for logging purposes. Logs are printed to the console with varying levels of severity:
- **Trace** (level 5): Detailed information used for debugging.
- **Debug** (level 4): Information useful for developers during debugging.
- **Info** (level 3): General operational information about what is happening.
- **Warning** (level 2): Indications that something unexpected happened but did not cause a failure.
- **Error** (level 1): Indicates an error occurred but was handled gracefully.
- **Critical** (level 0): Serious errors indicating that the program may not be able to continue running.
You can adjust the logging level through the configuration file by setting ``log_level``.

## Contributing
Contributions are welcome! Feel free to submit a pull request or open an issue if you encounter any problems or have suggestions for improvements.

## Author
[FarnoodID](https://github.com/FarnoodID)

