#!/usr/bin/env python3
# Program is developed on Ubuntu 22.04.2 and Python 3.10.
# Functions to extract various forensic artifacts from Linux memory dumps using Volatility3.
# Version: 1.0

import re
import subprocess


sockstat_pattern = re.compile(
    r"(?P<netns>\d+)\s+"
    r"(?P<process_name>\S(?:.*?\S)?)\s+"  # match any non-whitespace name
    r"(?P<pid>\d+)\s+"
    r"(?P<tid>\d+)\s+"
    r"(?P<fd>\d+)\s+"
    r"(?P<sock_offset>\S+)\s+"
    r"(?P<family>\S+)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<protocol>\S+)\s+"
    r"(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<source_port>\d+)\s+"
    r"(?P<dest_ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<dest_port>\d+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<filter>-)"
)

pslist_pattern = re.compile(
    r"^(?P<offset>0x[0-9a-f]+)\s+"
    r"(?P<pid>\d+)\s+"
    r"(?P<tid>\d+)\s+"
    r"(?P<ppid>\d+)\s+"
    r"(?P<comm>[^\t]+?)\s+"
    r"(?P<uid>\d+)\s+"
    r"(?P<gid>\d+)\s+"
    r"(?P<euid>\d+)\s+"
    r"(?P<egid>\d+)\s+"
    r"(?P<creation_time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ UTC)\s+"
    r"(?P<file_output>\S+)"
)

procmap_pattern = re.compile(
    r"^(?P<pid>\d+)\s+"                       # PID
    r"(?P<process>[^\t]+?)\s+"                # Process name (can have spaces/dashes)
    r"(?P<start>0x[0-9a-f]+)\s+"              # Start address
    r"(?P<end>0x[0-9a-f]+)\s+"                # End address
    r"(?P<flags>[rwxps\-\\]+)\s+"             # Flags (e.g., rw-, r-x, ---)
    r"(?P<pg_off>0x[0-9a-f]+)\s+"             # Page offset
    r"(?P<major>\d+)\s+"                      # Major
    r"(?P<minor>\d+)\s+"                      # Minor
    r"(?P<inode>\d+)\s+"                      # Inode
    r"(?P<file_path>.+?)\s+"                  # File path 
    r"Disabled$"                              # Disabled marker
)



ip_addr_pattern = re.compile(
    r"(?P<netns>\d+)\s+"                         # NetNS
    r"(?P<index>\d+)\s+"                         # Index
    r"(?P<interface>\S+)\s+"                     # Interface
    r"(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+"  # MAC address
    r"(?P<promiscuous>True|False)\s+"           # Promiscuous
    r"(?P<ip>\S+)\s+"                            # IP address (IPv4 or IPv6)
    r"(?P<prefix>\d+)\s+"                        # Prefix
    r"(?P<scope>\S+)\s+"                         # Scope (e.g., global, link)
    r"(?P<state>\S+)"                            # State (e.g., UP)
)

lsof_pattern = re.compile(
    r"(?P<pid>\d+)\s+"                             # PID
    r"(?P<tid>\d+)\s+"                             # TID
    r"(?P<process>\S+)\s+"                         # Process name
    r"(?P<fd>\d+)\s+"                              # File descriptor
    r"(?P<path>\S+)\s+"                            # Path (can be socket:[...] or anon_inode:[...])
    r"(?P<device>\d+:\d+)\s+"                      # Device
    r"(?P<inode>\d+)\s+"                           # Inode
    r"(?P<type>\S+)\s+"                            # Type (e.g., SOCK, CHR)
    r"(?P<mode>\S+)\s+"                            # Mode (e.g., srwxrwxrwx)
    r"(?P<changed>-|(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ UTC))\s+"  # Changed timestamp or -
    r"(?P<modified>-|(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ UTC))\s+" # Modified timestamp or -
    r"(?P<accessed>-|(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ UTC))\s+" # Accessed timestamp or -
    r"(?P<size>\d+)"                               # Size
)




def execute_system_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def starts_with_integer(line):
    return bool(re.match(r'^\d+', line.lstrip()))


def analyze_connection(source_port, dest_port, pid, network_type, analysis_ioc, indicators):
    direction = None

    # Additional heuristic based on port numbers
    try:
        source_port = int(source_port)
        dest_port = int(dest_port)

        suspicious_shell_ports = {4444, 1337, 5555, 6666, 9001}

        if dest_port in suspicious_shell_ports and source_port >= 32768:
                direction = "Suspicious Outgoing"
        elif source_port in suspicious_shell_ports and dest_port >= 32768:
            direction = "Suspicious Incoming"
        elif source_port >= 32768 and dest_port < 32768:
            direction = "Outgoing"
        elif dest_port >= 32768 and source_port < 32768:
            direction = "Incoming"

    except ValueError:
        direction = "Unknown"

    if direction and pid not in analysis_ioc:
        analysis_ioc[pid] = []

    if direction:
        protocol = network_type.upper()
        if protocol in ["TCP", "UDP", "TCP6", "UDP6"]:
            message = f"ESTABLISHED {direction} {protocol} connection"
            if message not in analysis_ioc[pid]:
                analysis_ioc[pid].append(message)
                if "connection_facets" not in indicators:
                    indicators["connection_facets"] = []
                normalized_direction = "Outgoing" if "Outgoing" in direction else "Incoming"
                indicators["connection_facets"].append(f"ESTABLISHED|{normalized_direction}|{protocol}")



def extract_network_information_from_dump(dump_file, analysis_ioc, indicators, debug=False, process_information=None, collect_process_info=False):
    print("Extracting Network Information from Dump...")

    network_info = execute_system_command(f"vol -f {dump_file} linux.sockstat | grep -E 'TCP|UDP' | grep ESTABLISHED")
    if debug:
        print(network_info)

    for line in network_info.splitlines():

        match = sockstat_pattern.match(line)
        if not match:
            continue
        
        info = match.groupdict()

        pid = info["pid"]

        source_ip = info["source_ip"]
        source_port = info["source_port"]
        dest_ip = info["dest_ip"]
        dest_port = info["dest_port"]
        network_type = info["protocol"]

        if collect_process_info:
            if pid not in process_information:
                process_information[pid] = dict()
            if "NetworkConnections" not in process_information[pid]:
                process_information[pid]["NetworkConnections"] = []
            
            process_information[pid]["NetworkConnections"].append({
                "Source IP": source_ip,
                "Source Port": source_port, 
                "Destination IP": dest_ip,
                "Destination Port": dest_port,
                "Protocol": network_type
            })

        analyze_connection(source_port, dest_port, pid, network_type, analysis_ioc, indicators)


def extract_process_information_from_dump(dump_file, analysis_ioc, indicators, debug=False, process_information=None, collect_process_info=False):
    print("Extracting Process Information from Dump...")

    for pid in analysis_ioc.keys():
        if collect_process_info:
            if pid not in process_information:
                process_information[pid] = dict()
            if "ProcessDetails" not in process_information[pid]:
                process_information[pid]["ProcessDetails"] = dict()

        process_info = execute_system_command(f"vol -f {dump_file} linux.pslist --pid {pid}")

        if debug:
            print(process_info)

        for line in process_info.splitlines():
            match = pslist_pattern.match(line)
            if not match:
                continue
            info = match.groupdict()

            if collect_process_info:
                process_information[pid]["ProcessDetails"] = {
                    "Process Name": info["comm"].strip(),
                    "Parent PID": info["ppid"],
                    "User ID": info["uid"],
                    "Group ID": info["gid"]
                }


def extract_memory_maps_from_dump(dump_file, analysis_ioc, indicators, debug=False, process_information=None, collect_process_info=False):


    MSG_ANON  = "RWX executable region mapped to Anonymous Mapping"
    MSG_LARGE = "RWX executable region mapped to Large Anonymous Mapping"
    MSG_DEV_ZERO = "RWX executable region mapped to /dev/zero"


    print("Extracting Memory Maps from Dump...")
    for pid in analysis_ioc.keys():

        if collect_process_info:
            if pid not in process_information:
                process_information[pid] = dict()
            if "MappedMemoryRegions" not in process_information[pid]:
                process_information[pid]["MappedMemoryRegions"] = []
        
        process_info = execute_system_command(f"vol -f {dump_file} linux.proc --pid {pid}")

        if debug:
            print(process_info)

        for line in process_info.splitlines():
            match = procmap_pattern.match(line)
            if not match:
                continue

            info = match.groupdict()
            file_path = info["file_path"].strip()
            flags = info["flags"].strip()
            if collect_process_info:
                process_information[pid]["MappedMemoryRegions"].append({
                    "File Path": file_path,
                    "Flags": flags,
                    "Start Address": info["start"],
                    "End Address": info["end"]
                })
                try:
                    process_name = process_information[pid]["ProcessDetails"]["Process Name"]
                except KeyError:
                    process_name = info["process"].strip()
            else:
                process_name = info["process"].strip()

            if process_name in file_path and flags == 'rwx':
                message = "RWX executable region mapped to main binary"
                if "rwx_to_main_binary" not in indicators:
                    indicators["rwx_to_main_binary"] = True
                if message not in analysis_ioc[pid]:
                    analysis_ioc[pid].append(message)

            if file_path == "Anonymous Mapping" and flags == 'rwx':
                start_addr = int(info["start"], 16)
                end_addr = int(info["end"], 16)

                map_size = end_addr - start_addr

                if map_size >= 0x100000:
                    # Prefer 'Large' and supersede 'Anonymous' if present
                    if MSG_ANON in analysis_ioc[pid]:
                        analysis_ioc[pid][analysis_ioc[pid].index(MSG_ANON)] = MSG_LARGE
                    elif MSG_LARGE not in analysis_ioc[pid]:
                        analysis_ioc[pid].append(MSG_LARGE)
                else:
                    # Add 'Anonymous' only if neither message exists
                    if MSG_ANON not in analysis_ioc[pid] and MSG_LARGE not in analysis_ioc[pid]:
                        analysis_ioc[pid].append(MSG_ANON)

                indicators["rwx_to_anon_mapping"] = True

            if "/dev/zero" in file_path and flags == 'rwx':
                indicators["rwx_to_dev_zero"] = True
                if MSG_DEV_ZERO not in analysis_ioc[pid]:
                    analysis_ioc[pid].append(MSG_DEV_ZERO)


def process_yara_scan_results(yara_scan_output):

    lines = yara_scan_output.strip().splitlines()
    entries = []
    current_offset = None
    hex_bytes = []
    ascii_string = ""

    for line in lines:
        # Check if line starts with an offset
        if re.match(r"^0x[0-9a-f]+", line):
            # Save previous entry if exists
            if current_offset:
                entries.append((current_offset, ' '.join(hex_bytes), ascii_string))
            # Start new entry
            current_offset = line.split()[0]
            hex_bytes = []
            ascii_string = ""
        else:
            # Extract hex and ASCII parts
            parts = line.strip().split()
            if parts:
                hex_part = parts[:-1]
                ascii_part = parts[-1]
                hex_bytes.extend(hex_part)
                ascii_string += ascii_part

    # Append last entry
    if current_offset:
        entries.append((current_offset, ' '.join(hex_bytes), ascii_string))
        # entries[current_offset] = ascii_string

    return entries


def extract_string_match_from_dump(dump_file, analysis_ioc, indicators, strings_of_interest, debug=False, process_information=None, collect_process_info=False):
    print("Extracting String Matches from Dump...")
    # Remove duplicates strings_of_interest
    strings_of_interest = list(set(strings_of_interest))

    for pid in analysis_ioc.keys():
        if collect_process_info:
            if pid not in process_information:
                process_information[pid] = dict()
            if "YARAStrings" not in process_information[pid]:
                process_information[pid]["YARAStrings"] = []
        for string in strings_of_interest:
            yara_scan = execute_system_command(f"vol -f {dump_file} linux.vmayarascan --yara-string {string} --pid {pid}")

            if debug:
                print(yara_scan)

            processed_result = process_yara_scan_results(yara_scan)

            if processed_result:

                if collect_process_info:
                    process_information[pid]["YARAStrings"].extend(processed_result)

                message = "suspicious string match in memory"
                if message.replace(" ", "_") not in indicators:
                    indicators[message.replace(" ", "_")] = True
                if message not in analysis_ioc[pid]:
                    analysis_ioc[pid].append(message)


def extract_network_addr_details_from_dump(dump_file, analysis_ioc, indicators, debug=False, process_information=None, collect_process_info=False):
    print("Extracting Network Address Details from Dump...")
    network_addr = execute_system_command(f"vol -f {dump_file} linux.ip.Addr | grep -vP '\slo\s'")

    if debug:
        print(network_addr)

    ip_address_list = []

    for line in network_addr.splitlines():
        match = ip_addr_pattern.match(line)
        if not match:
            continue

        info = match.groupdict()
        ip_address = info["ip"]
        print("Extracted IP Address:", ip_address)
        ip_address_list.append(ip_address)

    for pid in analysis_ioc.keys():
        if collect_process_info:
            if pid not in process_information:
                process_information[pid] = dict()
            if "NetworkInterfaceDetails" not in process_information[pid]:
                process_information[pid]["NetworkInterfaceDetails"] = []

            if collect_process_info:
                process_information[pid]["NetworkInterfaceDetails"].append({
                    "IP Address": ip_address_list,
                })

