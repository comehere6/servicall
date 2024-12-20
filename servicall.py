import signal
import itertools
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from itertools import islice

# isemtelephony -> 돌리다 보면 DoS나면서 service list도 안쳐짐 근데 크래시 로그는 안남음
# adb shell service call media.audio_policy 47 i32 "1" i32 "4294967294" i64 "3.141592" -> audioserver sigabrt

# Define the parcels
parcels = {
    "i32": [1, 0, 65535, 0xfffffffe, 0xffffffff],
    "i64": [0xfffffffffffffffe, 0xffffffffffffffff, 1, -1, 3.141592],
    "f": [0xff, 0xffff],
    "s16": ["A" * 10, "A" * 100, "\\xff\\xff\\xff\\xff\\xff\\xff\\xfc"]
}

# Shared variables
execution_count = 0
terminate_flag = 0

# Function to divide work among chunks
def chunked_iterable(iterable, size):
    """
    Divide an iterable into chunks of a given size.
    """
    iterator = iter(iterable)
    for first in iterator:
        yield list(islice(itertools.chain([first], iterator), size - 1))

def write_log(log_filename, cmd):
    """
    Writeing logfile when crash detected
    """
    with open(log_filename, 'w') as log_file:
        log_file.write("================================ Command ===============================\n\n")
        log_file.write(cmd + "\n\n")
        log_file.write("======================================================================\n\n")
        log_file.write("\nCrash Logs:\n")
        crash_logs = subprocess.run("adb logcat -b crash -d", shell=True, capture_output=True, text=True)
        log_file.write(crash_logs.stdout)

# Function to execute the fuzz command
# Function to execute the fuzz command
def execute_fuzz_command(fuzz_commands):
    """
    Execute a list of fuzz commands.
    """
    global execution_count, terminate_flag
    results = []
    not_a_data_message_count = 0  # Counter for "Not a data message" responses
    try:
        for cmd_tuple in fuzz_commands:
            if terminate_flag:
                return results  # Exit early if termination is signaled

            cmd = cmd_tuple[0]  # Extract the actual command string from the tuple
            code = cmd_tuple[1]  

            # Run the command using subprocess
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = f"Command: {cmd}\nResult:\n{result.stdout}\nError:\n{result.stderr}\n"

            # Increment execution count
            execution_count += 1

            # Check if the response is "Not a data message"
            if "Not a data message" in result.stdout:
                not_a_data_message_count += 1

            if "Function not implemented" in result.stdout or "Function not implemented" in result.stderr:
                print(f"[{execution_count}] Skipping CODE {code}: Function not implemented.")
                return results

            # Handle specific error conditions
            if "device offline"  in result.stderr or "does not exist" in result.stderr:
                print(f"[{execution_count}] Critical Error: {result.stderr.strip()} - Terminating all processes.")
                terminate_flag = 1
                break

            print(f"[{execution_count}] {output}")
            results.append(output)

        # Check if all commands returned "Not a data message"
        if not_a_data_message_count == len(fuzz_commands):
            print("[!] All responses are 'Not a data message'. Terminating all processes.")
            terminate_flag = 1

    except subprocess.TimeoutExpired:
        print(f"Command timed out: {cmd}")
    except Exception as e:
        print(f"Error executing command: {cmd}\n{e}")
    finally:
        return terminate_flag


# Fuzzer logic
def Fuzz(service_name, start_code=1, max_commands_per_code=100):
    """
    Generate fuzz commands grouped by transaction codes.
    Limit the number of commands per CODE.
    """
    fuzz_commands_by_code = {}
    CODE = start_code
    while CODE <= 128:
        if terminate_flag:
            break

        fuzz_commands = []
        command_count = 0  # Track the number of commands generated for this CODE

        for args_count in range(3, 6):  # Reduce args_count to limit combinations
            for args_schema in itertools.combinations(parcels.keys(), args_count):
                arg_collection = []
                for arg_type in args_schema:
                    for current_arg_value in parcels[arg_type]:
                        arg_collection.append(f"{arg_type} \"{current_arg_value}\"")

                for fuzzed_args in itertools.combinations(arg_collection, args_count):
                    if command_count >= max_commands_per_code:  # Limit commands per CODE
                        break

                    str_args = " ".join(fuzzed_args)
                    FUZZCMD = f"adb shell service call {service_name} {CODE} {str_args}"
                    fuzz_commands.append((FUZZCMD, CODE))
                    command_count += 1

                if command_count >= max_commands_per_code:
                    break

            if command_count >= max_commands_per_code:
                break

        if fuzz_commands:
            fuzz_commands_by_code[CODE] = fuzz_commands

        CODE += 1

    return fuzz_commands_by_code

def main(service_name, start_code, max_commands_per_code, num_processes):
    global terminate_flag, execution_count
    try:
        # Generate fuzz commands grouped by transaction codes
        fuzz_commands_by_code = Fuzz(service_name, start_code, max_commands_per_code)

        with ProcessPoolExecutor(max_workers=num_processes) as executor:
            for code, commands in fuzz_commands_by_code.items():
                print(f"main terminate_flag:{terminate_flag}")
                if terminate_flag:
                    print("[!] Termination flag detected. Stopping further processing.")
                    break

                print(f"[!] Processing CODE {code} with {len(commands)} commands...")

                chunked_commands = list(chunked_iterable(commands, len(commands) // num_processes or 1))
                futures = [executor.submit(execute_fuzz_command, chunk) for chunk in chunked_commands]

                for future in as_completed(futures):
                    try:
                        if terminate_flag < future.result():  # Wait for task completion
                            terminate_flag = future.result()
                    except Exception as exc:
                        print(f"Task generated an exception: {exc}")
                    if terminate_flag:
                        break

    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt detected. Cleaning up...")
        terminate_flag = -1
    finally:
        print(f"[!] Total executed commands: {execution_count}")
        print("[!] Cleanup complete.")
        return terminate_flag

# Entry point
if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python fuzz_service.py <service_name> <start_transaction_code> <max_commands_per_code> <num_processes>")
        sys.exit(1)

    service_name = sys.argv[1]
    start_code = int(sys.argv[2])
    max_commands_per_code = int(sys.argv[3])
    num_processes = int(sys.argv[4])  # Number of processes
    while(1):
        handle = main(service_name, start_code, max_commands_per_code, num_processes)
        print(f"Handle : {handle}")

        if handle:
            print("ByeBye...")
            break

