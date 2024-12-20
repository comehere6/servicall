# ⌚ WatchOut!

We are **WatchOut**, a smartwatch vulnerability analysis team from **BOB (Best of the Best)** in South Korea.

Our mission is to enhance the security of smartwatches through rigorous research and testing.

# Overview

This repository contains a Python-based fuzzer designed to test Android system services for vulnerabilities by sending fuzzed inputs to transaction codes. The goal of this tool is to discover potential crashes or abnormal behavior in system services, such as `audioserver`.

## Features

- **Dynamic Command Generation:** Automatically generates fuzz commands with varied argument types and values.
- **Parallel Processing:** Uses Python's `concurrent.futures.ProcessPoolExecutor` for parallel execution of fuzz commands.
- **Crash Detection:** Monitors logcat for crash logs and saves them to a log file when a crash is detected.
- **Execution Limits:** Allows limiting the number of commands per transaction code for efficient fuzzing.

## Prerequisites

- Python 3.8+
- `adb` (Android Debug Bridge) installed and added to your PATH.
- A rooted Android device or emulator connected via `adb`.
- A working Python environment with the following libraries installed:
  - `concurrent.futures`
  - `subprocess`
  - `itertools`

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/android-service-fuzzer.git
   cd android-service-fuzzer
   ```

2. Install dependencies (if not already installed):

   ```bash
   pip install -r requirements.txt
   ```

3. Connect your Android device via `adb` and verify the connection:

   ```bash
   adb devices
   ```

## Usage

Run the fuzzer with the following command:

```bash
python fuzz_service.py <service_name> <start_transaction_code> <max_commands_per_code> <num_processes>
```

### Arguments

- `<service_name>`: The name of the Android service to fuzz (e.g., `media.audio_policy`).
- `<start_transaction_code>`: The starting transaction code to fuzz (e.g., `1`).
- `<max_commands_per_code>`: The maximum number of commands to generate per transaction code.
- `<num_processes>`: The number of parallel processes to use for fuzzing.

### Example

To fuzz the `media.audio_policy` service starting from transaction code `47`, generating up to `100` commands per code, using `4` parallel processes:

```bash
python fuzz_service.py media.audio_policy 47 100 4
```

## Output

- **Logs:**

  - Crash logs are saved in the current directory when a crash is detected.
  - Each log includes the executed command and the corresponding crash logs from `adb logcat`.

- **Terminal Output:**

  - Displays the status of executed commands, including success, errors, and crashes.

## Notes

- This tool is experimental and should be used responsibly. Only test on devices or emulators that you own or have explicit permission to test.
- Some commands may cause the target service to crash or become unresponsive. Restart the service or device if necessary.
- The tool includes a termination flag to stop all processes if critical errors are detected (e.g., device disconnects).

## Disclaimer

Use this tool at your own risk. The author is not responsible for any damage caused by the use of this software.

