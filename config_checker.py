import argparse
import ansible_runner
from colorama import Fore, Style, init
import re

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Run MD5 checksum tasks based on a configuration file and optionally check kernel versions.',
        epilog='Config file format: Each line should list one file or directory. For directories, add a "*" at the end of the line to check all files in the directory.\n'
               'Use -k to check kernel versions across all specified hosts.')
    parser.add_argument('-i', '--inventory', default='./inventory.yaml',
                        help='Path to the inventory file. Default is "./inventory.yaml".')
    parser.add_argument('-f', '--config_file', default='./config_checker.config',
                        help='Path to the configuration file. Default is "./config_checker.config".')
    parser.add_argument('-k', '--check_kernel', action='store_true',
                        help='Include this option to check the kernel version across all hosts.')
    parser.add_argument('hosts', help='Hosts or group to target, as specified in the inventory.')
    return parser.parse_args()

def read_config_file(file_name):
    with open(file_name, 'r') as file:
        lines = file.readlines()
    return [line.strip() for line in lines if line.strip()]

def run_ansible_tasks(inventory, hosts, files, check_kernel):
    init()  # Initialize colorama for colored output
    results = {}

    for entry in files:
        if entry.endswith('*'):
            directory = entry[:-1]  # Remove the asterisk
            command = f"find {directory} -type f -exec md5sum {{}} \;"
            print(f"Checking all files in directory: {directory}...")
            result = ansible_runner.run(
                private_data_dir='.',
                inventory=inventory,
                module='shell',
                module_args=command,
                host_pattern=hosts,
                quiet=True
            )
            process_directory_result(result, results)
        else:
            command = f"md5sum {entry} || echo '{entry} does not exist'"
            print(f"Checking {entry}...")
            result = ansible_runner.run(
                private_data_dir='.',
                inventory=inventory,
                module='shell',
                module_args=command,
                host_pattern=hosts,
                quiet=True
            )
            process_file_result(result, entry, results)

    if check_kernel:
        print("Checking kernel versions...")
        kernel_versions = get_kernel_versions(inventory, hosts)
        results['Kernel Version'] = kernel_versions

    return results

def process_directory_result(result, results):
    if result.status == 'successful':
        for event in result.events:
            if 'runner_on_ok' in event['event']:
                host = event['event_data']['host']
                stdout_lines = event['event_data']['res']['stdout_lines']
                for line in stdout_lines:
                    checksum, file_path = line.split(maxsplit=1)
                    if file_path not in results:
                        results[file_path] = {}
                    if checksum not in results[file_path]:
                        results[file_path][checksum] = []
                    results[file_path][checksum].append(host)

def process_file_result(result, entry, results):
    results[entry] = {}
    if result.status == 'successful':
        for event in result.events:
            if 'runner_on_ok' in event['event']:
                host = event['event_data']['host']
                stdout = event['event_data']['res']['stdout']
                if "does not exist" in stdout:
                    results[entry]["File does not exist"] = results[entry].get("File does not exist", []) + [host]
                else:
                    checksum, _ = stdout.split(maxsplit=1)
                    results[entry][checksum] = results[entry].get(checksum, []) + [host]

def get_kernel_versions(inventory, hosts):
    command = 'uname -r'
    result = ansible_runner.run(
        private_data_dir='.',
        inventory=inventory,
        module='shell',
        module_args=command,
        host_pattern=hosts,
        quiet=True
    )
    kernels = {}
    if result.status == 'successful':
        for event in result.events:
            if 'runner_on_ok' in event['event']:
                host = event['event_data']['host']
                kernel_version = event['event_data']['res']['stdout'].strip()
                kernels[host] = kernel_version
    return kernels

def display_kernel_versions(data):
    kernel_versions = set(data.values())
    if len(kernel_versions) == 1:
        version = next(iter(kernel_versions))
        print(Fore.GREEN + f"Kernel Version is the same across all hosts: {version}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "Kernel Version differs across hosts:" + Style.RESET_ALL)
        sorted_versions = sorted(data.items(), key=lambda item: natural_sort_key(item[0]))
        for host, version in sorted_versions:
            print(f"  {host}: {version}")

def display_results(results):
    print("\n" + "-"*50 + "\n")
    for file_path, data in results.items():
        if file_path == 'Kernel Version':
            display_kernel_versions(data)
        elif isinstance(data, dict):
            display_file_checksums(file_path, data)
        else:
            print(f"{file_path} has unexpected data format in results.")
    print()

def display_file_checksums(file_path, data):
    if "File does not exist" in data and len(data) == 1:
        print(Fore.YELLOW + f"{file_path} is missing from all hosts:" + Style.RESET_ALL)
        for host in sorted(data["File does not exist"], key=natural_sort_key):
            print(f"  {host}")
    elif len(data) == 1:
        checksum = next(iter(data))
        print(Fore.GREEN + f"{file_path} is the same across all hosts with checksum: {checksum}" + Style.RESET_ALL)
    else:
        print(f"{file_path} differs across hosts:")
        for checksum, hosts in sorted(data.items(), key=lambda x: x[0]):
            if checksum == "File does not exist":
                print(Fore.YELLOW + "Missing from the following hosts:" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"  Checksum: {checksum}" + Style.RESET_ALL)
            for host in sorted(hosts, key=natural_sort_key):
                print(f"    Host: {host}")

def natural_sort_key(s):
    """Helper function to sort strings with numeric components in natural order."""
    return [int(text) if text.isdigit() else text.lower() for text in re.split('([0-9]+)', s)]

if __name__ == "__main__":
    args = parse_arguments()
    files_to_check = read_config_file(args.config_file) if not args.check_kernel else []
    results = run_ansible_tasks(args.inventory, args.hosts, files_to_check, args.check_kernel)
    display_results(results)
