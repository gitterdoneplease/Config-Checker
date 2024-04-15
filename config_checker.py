import argparse
import ansible_runner
import re
from colorama import Fore, Style, init

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
            all_files = get_all_files_in_directory(directory, inventory, hosts)
            for file in all_files:
                print(f"Checking {file}...")
                results[file] = get_checksums_for_file(file, inventory, hosts)
        else:
            print(f"Checking {entry}...")
            results[entry] = get_checksums_for_file(entry, inventory, hosts)

    if check_kernel:
        print("Checking kernel versions...")
        results['Kernel Version'] = get_kernel_versions(inventory, hosts)

    print("\n" + "-"*50 + "\n")  # Separator between checking and results output
    return results

def get_all_files_in_directory(directory, inventory, hosts):
    unique_files = set()
    list_files_result = ansible_runner.run(
        private_data_dir='.',
        inventory=inventory,
        module='shell',
        module_args=f'ls {directory}',
        host_pattern=hosts,
        quiet=True
    )
    if list_files_result.status == 'successful':
        for event in list_files_result.events:
            if event['event'] == 'runner_on_ok':
                files = event['event_data']['res']['stdout'].split()
                unique_files.update([f"{directory}/{file}" for file in files])
    return unique_files

def get_checksums_for_file(file_path, inventory, hosts):
    checksum_result = ansible_runner.run(
        private_data_dir='.',
        inventory=inventory,
        module='shell',
        module_args=f'if [ -f {file_path} ]; then md5sum {file_path}; else echo "File does not exist"; fi',
        host_pattern=hosts,
        quiet=True
    )
    checksums = {}
    if checksum_result.status == 'successful':
        for event in checksum_result.events:
            if event['event'] == 'runner_on_ok':
                host = event['event_data']['host']
                output = event['event_data']['res']['stdout']
                if output == "File does not exist":
                    checksums[host] = "File does not exist"
                else:
                    md5sum = output.split()[0]
                    checksums[host] = md5sum
    return checksums

def get_kernel_versions(inventory, hosts):
    kernel_result = ansible_runner.run(
        private_data_dir='.',
        inventory=inventory,
        module='shell',
        module_args='uname -r',
        host_pattern=hosts,
        quiet=True
    )
    kernels = {}
    if kernel_result.status == 'successful':
        for event in kernel_result.events:
            if event['event'] == 'runner_on_ok':
                host = event['event_data']['host']
                kernel_version = event['event_data']['res']['stdout']
                kernels[host] = kernel_version
    return kernels

def compare_checksums(results):
    for item, values in results.items():
        # Collect all unique checksums and the hosts associated with each checksum
        checksums = {}
        for host, checksum in values.items():
            if checksum not in checksums:
                checksums[checksum] = []
            checksums[checksum].append(host)
        
        # Sort hosts within each checksum group
        for checksum in checksums:
            checksums[checksum] = sorted(checksums[checksum], key=lambda x: int(re.search(r'\d+', x).group()))

        if len(checksums) == 1 and next(iter(checksums.values()))[0] != "File does not exist":  # All the same checksum
            print(Fore.GREEN + f"{item} is the same across all hosts with checksum: {next(iter(checksums))}" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"{item} differs across hosts:" + Style.RESET_ALL)
            if "File does not exist" in checksums:
                print(Fore.YELLOW + "Missing from the following hosts:" + Style.RESET_ALL)
                for host in checksums["File does not exist"]:
                    print(f"  {host}")
                del checksums["File does not exist"]  # Remove the missing file entry for further processing

            # Sort checksums by the first host number in each group
            for checksum, hosts in sorted(checksums.items(), key=lambda x: int(re.search(r'\d+', x[1][0]).group())):
                print(f"  Checksum: {checksum}")
                for host in hosts:
                    print(f"    Host: {host}")

def print_checksum_groups(item, values):
    # Sorting values by checksum and then each host group
    sorted_values = {}
    for host, value in values.items():
        if value not in sorted_values:
            sorted_values[value] = []
        sorted_values[value].append(host)
    
    # Sorting checksums to ensure consistent order
    for value, hosts in sorted(sorted_values.items(), key=lambda x: x[0]):
        print(Fore.RED + f"{item} differs across hosts:" + Style.RESET_ALL)
        print(f"  Checksum: {value}")
        sorted_hosts = sorted(hosts, key=lambda x: int(re.search(r'\d+', x).group()))
        for host in sorted_hosts:
            print(f"    Host: {host}")

if __name__ == "__main__":
    args = parse_arguments()
    files_to_check = read_config_file(args.config_file) if not args.check_kernel else []
    results = run_ansible_tasks(args.inventory, args.hosts, files_to_check, args.check_kernel)
    compare_checksums(results)
