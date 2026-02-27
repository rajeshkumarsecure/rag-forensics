import ipaddress
import socket
import os
import re
import struct
import subprocess
from typing import Any, List, Dict, Iterable, Optional, Set, Tuple


NETSCAN_LINE_RE = re.compile(
    r"^(0x[0-9a-fA-F]+)\s+"
    r"(TCPv4|TCPv6|UDPv4|UDPv6)\s+"
    r"(\S+)\s+(\d+)\s+"
    r"(\S+)\s+(\d+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s*"
    r"(.*)$"
)

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
    r"(?P<source_ip>\S+)\s+"
    r"(?P<source_port>\d+)\s+"
    r"(?P<dest_ip>\S+)\s+"
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

FD_TO_NAME = {
    "0": "STDIN",
    "1": "STDOUT",
    "2": "STDERR",
}


# Canonical path detectors
socket_path_re = re.compile(r"\bsocket:\[(?P<sid>\d+)\]")
pipe_path_re   = re.compile(r"\bpipe:\[(?P<pid>\d+)\]")
anon_inode_re  = re.compile(r"\banon_inode:\[(?P<aid>\d+)\]")
pty_re         = re.compile(r"^/dev/pts/(?P<pts>\d+)$")
tty_re         = re.compile(r"^/dev/tty(?P<tty>.+)$")
devnull_re     = re.compile(r"^/dev/null$")



def execute_system_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def starts_with_integer(line):
    return bool(re.match(r'^\d+', line.lstrip()))


def _classify_connection_direction(source_port, dest_port) -> str:
    try:
        source_port = int(source_port)
        dest_port = int(dest_port)

        suspicious_shell_ports = {4444, 1337, 5555, 6666, 9001}

        if dest_port in suspicious_shell_ports and source_port >= 32768:
            return "Suspicious Outgoing"
        if source_port in suspicious_shell_ports and dest_port >= 32768:
            return "Suspicious Incoming"
        if source_port >= 32768 and dest_port < 32768:
            return "Outgoing"
        if dest_port >= 32768 and source_port < 32768:
            return "Incoming"
    except ValueError:
        return "Unknown"

    return "Unknown"


def _normalize_protocol_name(protocol: Optional[str]) -> str:
    p = str(protocol or "").upper()
    if p.startswith("TCP"):
        return "TCP"
    if p.startswith("UDP"):
        return "UDP"
    return p or "UNKNOWN"


def analyze_connection(source_port, dest_port, pid, network_type, analysis_ioc, indicators):
    direction = _classify_connection_direction(source_port, dest_port)

    if direction and pid not in analysis_ioc:
        analysis_ioc[pid] = []

    if direction:
        protocol = _normalize_protocol_name(network_type)
        if protocol in ["TCP", "UDP", "SCTP"]:
            message = f"ESTABLISHED {direction} {protocol} connection"
            if message not in analysis_ioc[pid]:
                analysis_ioc[pid].append(message)
                if "connection_facets" not in indicators:
                    indicators["connection_facets"] = []
                normalized_direction = "Outgoing" if "Outgoing" in direction else "Incoming"
                indicators["connection_facets"].append(f"ESTABLISHED|{normalized_direction}|Network")

def _looks_like_windows_info(text: str) -> bool:
    if not text:
        return False
    markers = [
        "NtMajorVersion",
        "NtMinorVersion",
        "NtSystemRoot",
        "NtProductType",
        "Kernel Base",
        "KdVersionBlock",
    ]
    return sum(1 for m in markers if m in text) >= 2


def obtain_os_info_from_dump(dump_file: str, debug: bool = False) -> str:
    """Best-effort OS detection for a Volatility-supported memory dump."""
    try:
        win = subprocess.run(
            ["vol", "-f", dump_file, "windows.info"],
            capture_output=True,
            text=True,
        )
        win_text = (win.stdout or "") + "\n" + (win.stderr or "")
        if debug:
            print(win_text)
        if win.returncode == 0 and _looks_like_windows_info(win_text):
            return "windows"
    except FileNotFoundError:
        raise RuntimeError("Could not find 'vol' on PATH. Install Volatility 3 or adjust PATH.")

    # Fallback: try a Linux-specific plugin if Windows failed.
    try:
        linux = subprocess.run(
            ["vol", "-f", dump_file, "banners"],
            capture_output=True,
            text=True,
        )
        linux_text = (linux.stdout or "") + "\n" + (linux.stderr or "")
        if debug:
            print(linux_text)
        if linux.returncode == 0 and "Linux version" in linux_text:
            return "linux"
    except Exception:
        pass

    # Unknown/unsupported dump type
    return "unknown"




def _is_private_ip(ip_str: str) -> bool:
    """Return True if ip_str is RFC1918 private / loopback / link-local / multicast etc."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        )
    except ValueError:
        return False

def _ip_in_cidrs(ip_str: str, cidrs: Iterable[str]) -> bool:
    """Check if IP is in any CIDR block."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False

def parse_vol_netscan(text: str) -> List[Dict]:
    """
    Parse Volatility 'windows.netstat' text output into a list of records.
    Works best when input resembles: Offset Proto LocalAddr LocalPort ForeignAddr ForeignPort State PID Owner Created
    """
    records = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Skip header-ish lines
        if line.lower().startswith("offset") or line.startswith("---"):
            continue

        m = NETSCAN_LINE_RE.match(line)
        if not m:
            # Some lines may be wrapped or malformed; ignore safely
            continue

        offset, proto, laddr, lport, faddr, fport, state, pid, owner, created = m.groups()
        # Normalize some Volatility placeholders
        pid_norm = None if pid in ("-", "—", "N/A") else pid
        owner_norm = None if owner in ("-", "—", "N/A") else owner
        created_norm = None if created.strip() in ("", "-", "—", "N/A") else created.strip()

        rec = {
            "offset": offset,
            "proto": proto,
            "local_addr": laddr,
            "local_port": int(lport),
            "foreign_addr": faddr,
            "foreign_port": int(fport),
            "state": state,
            "pid": None if pid_norm is None else int(pid_norm) if pid_norm.isdigit() else pid_norm,
            "owner": owner_norm,
            "created": created_norm,
            "raw": line,
        }
        records.append(rec)
    return records

def filter_suspicious_connections(
    records: List[Dict],
    *,
    allowlist_cidrs: Optional[Iterable[str]] = None,
    allowlist_ips: Optional[Iterable[str]] = None,
    allowlist_domains: Optional[Iterable[str]] = None,  # placeholder if you later enrich with DNS
    suspicious_ports: Optional[Set[int]] = None,
    require_established: bool = True,
    flag_missing_pid_owner: bool = True,
    flag_public_ip: bool = True,
    flag_lan_443: bool = False,
) -> List[Dict]:
    """
    Heuristic filter for suspicious netscan connections.

    - allowlist_cidrs: CIDRs that should NOT be flagged (e.g., Microsoft ranges you trust)
    - allowlist_ips: specific remote IPs that should NOT be flagged (e.g., your corp proxies, lab endpoints)
    - suspicious_ports: remote ports to focus on (default: {443, 80, 53, 22, 3389, 4444, 8443, 9001, 12345})
    - require_established: only flag ESTABLISHED (useful for C2), else include others
    - flag_missing_pid_owner: flag when PID/Owner/Created are missing or unknown
    - flag_public_ip: flag public remote IPs not in allowlist
    - flag_lan_443: optionally flag RFC1918-to-RFC1918 443 (for internal handler / lateral movement)
    """
    allowlist_cidrs = list(allowlist_cidrs or [])
    allowlist_ips = set(allowlist_ips or [])
    suspicious_ports = suspicious_ports or {443, 80, 53, 22, 3389, 4444, 8443, 9001, 12345}

    suspicious = []

    for r in records:
        proto = r["proto"]
        # We mostly care about TCP connections for this use-case
        if not proto.startswith("TCP"):
            continue

        if require_established and r["state"].upper() != "ESTABLISHED":
            continue

        faddr = r["foreign_addr"]
        fport = r["foreign_port"]
        laddr = r["local_addr"]

        # If foreign address is "*" or "::" (listen) skip; those are not outbound connections
        if faddr in ("*", "0.0.0.0", "::"):
            continue

        # Allowlist checks
        if faddr in allowlist_ips:
            continue
        if allowlist_cidrs and _ip_in_cidrs(faddr, allowlist_cidrs):
            continue

        reasons = []

        # Focus on interesting ports (esp 443)
        if fport in suspicious_ports:
            reasons.append(f"remote_port={fport}")

        # Missing attribution (common in injected/hidden scenarios)
        if flag_missing_pid_owner:
            if r["pid"] is None or r["owner"] is None or r["created"] is None:
                reasons.append("missing_pid/owner/created")

        # Public IP not allowlisted
        if flag_public_ip:
            # Flag if remote is not private (public) and not allowlisted
            if not _is_private_ip(faddr):
                reasons.append("public_remote_ip")

        # Optional: LAN-to-LAN 443
        if flag_lan_443 and fport == 443:
            if _is_private_ip(laddr) and _is_private_ip(faddr):
                reasons.append("lan_to_lan_443")

        # Only consider suspicious if we have at least one reason
        if reasons:
            rr = dict(r)
            rr["reasons"] = reasons
            suspicious.append(rr)

    return suspicious

# Convenience wrapper: take raw text directly
def suspicious_from_netscan_text(
    netscan_text: str,
    *,
    allowlist_cidrs: Optional[Iterable[str]] = None,
    allowlist_ips: Optional[Iterable[str]] = None,
    **kwargs
) -> List[Dict]:
    records = parse_vol_netscan(netscan_text)
    return filter_suspicious_connections(
        records,
        allowlist_cidrs=allowlist_cidrs,
        allowlist_ips=allowlist_ips,
        **kwargs
    )


def extract_network_information_from_dump(dump_file, analysis_ioc, indicators, debug=False, process_information=None, collect_process_info=False):
    print("Extracting Network Information from Dump...")

    network_info = execute_system_command(f"vol -f {dump_file} linux.sockstat | grep -E 'TCP|UDP|SCTP' | grep ESTABLISHED")
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


def process_windows_network_info_from_dump(dump_file, suspicious_network_info, debug=False):

        network_info = execute_system_command(f"vol -f {dump_file} windows.netstat")
        # if debug:
        #     print(network_info)

        allowlist_ips = {}

        sus = suspicious_from_netscan_text(
            network_info,
            allowlist_ips=allowlist_ips,
            suspicious_ports={443},          # focus only on TLS
            require_established=True,
            flag_missing_pid_owner=True,
            flag_public_ip=True,
            flag_lan_443=False,              # set True if you want to catch internal handler
        )

        for s in sus:
            direction = _classify_connection_direction(s.get("local_port"), s.get("foreign_port"))
            # print(s["foreign_addr"], s["foreign_port"], s["state"], s["pid"], s["owner"], "=>", s["reasons"])
            suspicious_network_info.append({
                "Local Address": s.get("local_addr"),
                "Local Port": s.get("local_port"),
                "Foreign Address": s["foreign_addr"],
                "Foreign Port": s["foreign_port"],
                "State": s["state"],
                "Protocol": s.get("proto"),
                "Connection Direction": direction,
                "PID": s["pid"],
                "Owner": s["owner"],
                "Reasons": s["reasons"]
            })


def ip_port_to_shellcode(ip: str, port: int) -> bytes:
    """
    Converts IPv4 + port into sockaddr_in byte sequence:
    02 00 | port (big-endian) | IPv4 bytes
    """
    af_inet = b"\x02\x00"
    port_be = struct.pack(">H", port)
    ip_bytes = socket.inet_aton(ip)
    return af_inet + port_be + ip_bytes


def check_suspicious_network_bytes_in_dump(
    suspicious_network_info: List[Dict[str, Any]],
    susp_process: Optional[List[Dict[str, Any]]] = None,
    dumps_dir: str = "dumps",
    analysis_ioc=None,
    indicators=None,
    debug: bool = False,
    process_information=None,
    collect_process_info: bool = False,
) -> List[Dict[str, Any]]:
    """
    For each suspicious network entry, convert Foreign Address + Foreign Port to a
    sockaddr_in-like 8-byte sequence and return matches ONLY when the full sequence
    is present contiguously in process dump files from `dumps_dir`.

    Designed for dumps produced by `windows.malfind --pid <pid> --dump`.
    """
    results: List[Dict[str, Any]] = []
    if analysis_ioc is None:
        analysis_ioc = {}
    if indicators is None:
        indicators = {}

    if not suspicious_network_info:
        return results

    dumps_dir_abs = os.path.abspath(dumps_dir)
    if not os.path.isdir(dumps_dir_abs):
        if debug:
            print(f"[NETWORK BYTE CHECK] dumps directory not found: {dumps_dir_abs}")
        return results

    all_dump_files = [
        os.path.join(dumps_dir_abs, name)
        for name in os.listdir(dumps_dir_abs)
        if os.path.isfile(os.path.join(dumps_dir_abs, name))
    ]
    if not all_dump_files:
        return results

    fallback_pids: List[int] = []
    for proc in (susp_process or []):
        proc_pid = proc.get("pid")
        if isinstance(proc_pid, int) and proc_pid not in fallback_pids:
            fallback_pids.append(proc_pid)

    for item in suspicious_network_info:
        ip_value = item.get("Foreign Address")
        port_value = item.get("Foreign Port")
        pid_value = item.get("PID")

        try:
            ip_str = str(ip_value)
            port_int = int(port_value)
            pid_int = int(pid_value) if pid_value is not None else None
            ip_bytes = socket.inet_aton(ip_str)
            port_be = struct.pack(">H", port_int)
            full_seq = ip_port_to_shellcode(ip_str, port_int)
        except Exception:
            continue

        candidate_files = all_dump_files
        if pid_int is not None:
            pid_tag = f"pid.{pid_int}."
            pid_specific = [path for path in all_dump_files if pid_tag in os.path.basename(path)]
            if pid_specific:
                candidate_files = pid_specific
        full_offsets: List[Dict[str, Any]] = []
        searched_ranges: List[Dict[str, Any]] = []

        if debug:
            print(f"[NETWORK BYTE CHECK] target={ip_str}:{port_int} pid={pid_int} seq={full_seq.hex()}")

        for dump_path in candidate_files:
            with open(dump_path, "rb") as fh:
                dump_bytes = fh.read()

            region_start = 0
            region_end = len(dump_bytes)
            searched_ranges.append(
                {
                    "file": dump_path,
                    "region_start": region_start,
                    "region_end": region_end,
                }
            )
            if debug:
                print(
                    f"[NETWORK BYTE CHECK] searching range file={dump_path} "
                    f"start={region_start} end={region_end}"
                )

            full_offset = dump_bytes.find(full_seq)
            if full_offset != -1:
                full_offsets.append(
                    {
                        "file": dump_path,
                        "offset": full_offset,
                        "region_start": region_start,
                        "region_end": region_end,
                    }
                )

        # Strict mode: only report when all 8 bytes match in sequence.
        if not full_offsets:
            if debug:
                print(f"[NETWORK BYTE CHECK] {ip_str}:{port_int} -> full=False")
            continue

        entry_result = {
            "ip": ip_str,
            "port": port_int,
            "pid": pid_int,
            "checked_files": candidate_files,
            "restricted_to_suspicious_thread_regions": False,
            "searched_ranges": searched_ranges,
            "full_sequence_present": True,
            "matched_sequence_hex": full_seq.hex(),
            "full_sequence_offsets": full_offsets,
            "source_entry": item,
        }
        results.append(entry_result)

        attributed_pids: List[int] = []
        if isinstance(pid_int, int):
            attributed_pids = [pid_int]
        else:
            # Try to infer PID from matched dump filenames like pid.<PID>.*
            inferred = []
            for hit in full_offsets:
                filename = os.path.basename(str(hit.get("file", "")))
                m = re.search(r"pid\.(\d+)\.", filename)
                if m:
                    parsed = int(m.group(1))
                    if parsed not in inferred:
                        inferred.append(parsed)
            attributed_pids = inferred or fallback_pids

        direction = item.get("Connection Direction") or _classify_connection_direction(
            item.get("Local Port"),
            port_int,
        )
        protocol = _normalize_protocol_name(item.get("Protocol") or "TCPv4")

        for target_pid in attributed_pids:
            if target_pid not in analysis_ioc:
                analysis_ioc[target_pid] = []

            if collect_process_info:
                if process_information is None:
                    process_information = {}
                if target_pid not in process_information:
                    process_information[target_pid] = {}
                if "NetworkByteSequenceMatches" not in process_information[target_pid]:
                    process_information[target_pid]["NetworkByteSequenceMatches"] = []

                process_information[target_pid]["NetworkByteSequenceMatches"].append(
                    {
                        "IP": ip_str,
                        "Port": port_int,
                        "MatchedSequenceHex": full_seq.hex(),
                        "MatchedFiles": list(dict.fromkeys([str(hit.get("file", "")) for hit in full_offsets if hit.get("file")])),
                        "MatchOffsets": full_offsets,
                        "ConnectionDirection": direction,
                        "Protocol": protocol,
                    }
                )

            if direction and direction != "Unknown":
                message = f"ESTABLISHED {direction} {protocol} connection"
                if message not in analysis_ioc[target_pid]:
                    analysis_ioc[target_pid].append(message)

                if "connection_facets" not in indicators:
                    indicators["connection_facets"] = []
                normalized_direction = "Outgoing" if "Outgoing" in direction else "Incoming"
                facet = f"ESTABLISHED|{normalized_direction}|Network"
                if facet not in indicators["connection_facets"]:
                    indicators["connection_facets"].append(facet)

            # matched_message = f"Socket byte sequence matched in malfind dump ({ip_str}:{port_int})"
            # if matched_message not in analysis_ioc[target_pid]:
            #     analysis_ioc[target_pid].append(matched_message)
            # indicators["socket_byte_sequence_matched_in_malfind_dump"] = True

        if debug and not attributed_pids:
            print(f"[NETWORK BYTE CHECK] matched bytes but could not attribute PID for {ip_str}:{port_int}")

        if debug:
            print(f"[NETWORK BYTE CHECK] {ip_str}:{port_int} -> full=True")

    return results


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

            if info["comm"].strip() == "sh" or info["comm"].strip() == "bash" or info["comm"].strip() == "zsh" or info["comm"].strip() == "dash" or info["comm"].strip() == "ksh" or info["comm"].strip() == "csh" or info["comm"].strip() == "tcsh" or info["comm"].strip() == "mksh" or info["comm"].strip() == "ksh93":
                message = "Shell Process with Network Connections Detected"
                if "shell_process_with_network_connections" not in indicators:
                    indicators["shell_process_with_network_connections"] = True
                if message not in analysis_ioc[pid]:
                    analysis_ioc[pid].append(message)

            if collect_process_info:
                process_information[pid]["ProcessDetails"] = {
                    "Process Name": info["comm"].strip(),
                    "Parent PID": info["ppid"],
                    "User ID": info["uid"],
                    "Group ID": info["gid"]
                }


def _safe_hex_to_int(value: str) -> Optional[int]:
    try:
        return int(value, 16)
    except Exception:
        return None


def obtain_process_with_suspicious_threads_from_dump(dump_file: str, debug=False, top_n: int = 10) -> List[Dict[str, Any]]:

    threads_info = execute_system_command(f"vol -f {dump_file} windows.threads")

    if debug:
        print(threads_info)

    candidates: List[Dict[str, Any]] = []

    def _is_probably_kernel_address(addr: Optional[int]) -> bool:
        if addr is None:
            return False
        return addr >= 0x800000000000

    for raw_line in threads_info.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Skip banner/header lines
        if not line.startswith("0x"):
            continue

        # Primary parse path: tab-separated columns
        parts = [p.strip() for p in raw_line.split("\t") if p.strip() != ""]
        if len(parts) < 9:
            # Fallback: split on 2+ spaces (less reliable if paths include spaces)
            parts = re.split(r"\s{2,}", line)
            if len(parts) < 9:
                continue

        # Take first 9 columns only
        ethread, pid_s, tid_s, start_addr_s, start_path, win32_addr_s, win32_path, create_time, exit_time = parts[:9]

        try:
            pid = int(pid_s)
            tid = int(tid_s)
        except ValueError:
            continue

        start_addr = _safe_hex_to_int(start_addr_s)
        win32_addr = _safe_hex_to_int(win32_addr_s)

        # Scoring heuristic
        score = 0
        reasons: List[str] = []
        start_is_kernel = _is_probably_kernel_address(start_addr)
        win32_is_kernel = _is_probably_kernel_address(win32_addr)

        # Unknown module mappings are high signal
        if start_path == "-":
            score += 3
            reasons.append("StartPath is unknown (-)")
        if win32_path == "-":
            score += 4
            reasons.append("Win32StartPath is unknown (-)")
        if start_path == "-" and win32_path == "-":
            score += 6
            reasons.append("Both start paths are unknown")

        # Unknown starts in kernel address space are common; down-rank them.
        if (start_path == "-" and start_is_kernel) and (win32_path == "-" and win32_is_kernel):
            score -= 8
            reasons.append("Likely kernel-space thread (reduced confidence)")

        # Same unknown address in both start fields can indicate injected thread trampoline/shellcode region
        if start_addr is not None and win32_addr is not None and start_addr == win32_addr:
            score += 2
            reasons.append("StartAddress equals Win32StartAddress")

        # Exclude common kernel/system thread noise
        if pid == 4:
            score -= 5
            reasons.append("PID 4 system-thread noise reduction")

        # User process with unknown starts is more suspicious than service/system baseline
        if pid > 4 and (start_path == "-" or win32_path == "-"):
            score += 2
            reasons.append("Unknown start in non-system PID")

        # User-like unknown start addresses are stronger than kernel-like unknown starts.
        if (start_path == "-" and not start_is_kernel) or (win32_path == "-" and not win32_is_kernel):
            score += 4
            reasons.append("Unknown start address appears user/private-space")

        if score <= 0:
            continue

        candidates.append(
            {
                "score": score,
                "pid": pid,
                "tid": tid,
                "ethread": ethread,
                "start_address": start_addr_s,
                "start_path": start_path,
                "win32_start_address": win32_addr_s,
                "win32_start_path": win32_path,
                "start_is_kernel": start_is_kernel,
                "win32_start_is_kernel": win32_is_kernel,
                "create_time": create_time,
                "exit_time": exit_time,
                "reasons": reasons,
            }
        )

    candidates.sort(
        key=lambda x: (
            x["score"],
            1 if (not x["start_is_kernel"] or not x["win32_start_is_kernel"]) else 0,
        ),
        reverse=True,
    )
    return candidates[:top_n]


def validate_sockets_for_suspicious_process(
    dump_file: str,
    susp_process: List[Dict[str, Any]],
    analysis_ioc,
    indicators,
    debug: bool = False,
    process_information=None,
    collect_process_info: bool = False,
) -> List[Dict[str, Any]]:
    """
    Validate suspicious thread candidates by checking whether their PIDs own AFD socket handles.

    Steps:
    - Parse `susp_process` to obtain unique PIDs.
    - Run `vol -f <dump_file> windows.handle --pid <pid> | grep -i Afd`.
    - If matches exist, add the full matching entries to `susp_process_with_sockets`.

    Returns:
        List of dicts with keys:
            - pid
            - suspicious_threads
            - socket_handle_entries
    """
    susp_process_with_sockets: List[Dict[str, Any]] = []
    if not susp_process:
        return susp_process_with_sockets

    pid_to_threads: Dict[int, List[Dict[str, Any]]] = {}
    for entry in susp_process:
        pid = entry.get("pid")
        if not isinstance(pid, int):
            continue
        if pid not in pid_to_threads:
            pid_to_threads[pid] = []
        pid_to_threads[pid].append(entry)

    for pid, threads_for_pid in pid_to_threads.items():
        cmd = f'vol -f "{dump_file}" windows.handle --pid {pid} | grep -i Afd'
        handle_output = execute_system_command(cmd)

        afd_entries = [ln.strip() for ln in handle_output.splitlines() if ln.strip()]
        if not afd_entries:
            continue

        pid_result = {
            "pid": pid,
            "suspicious_threads": threads_for_pid,
            "socket_handle_entries": afd_entries,
        }
        susp_process_with_sockets.append(pid_result)

        if collect_process_info:
            if process_information is None:
                process_information = {}
            if pid not in process_information:
                process_information[pid] = {}
            if "SocketHandleEntries" not in process_information[pid]:
                process_information[pid]["SocketHandleEntries"] = []
            if "SuspiciousThreads" not in process_information[pid]:
                process_information[pid]["SuspiciousThreads"] = []

            process_information[pid]["SocketHandleEntries"].extend(afd_entries)
            process_information[pid]["SuspiciousThreads"].extend(threads_for_pid)

        if pid not in analysis_ioc:
            analysis_ioc[pid] = []
        message = f"Process has AFD socket handles"
        analysis_ioc[pid].append(message)
        if "process_has_afd_socket_handles" not in indicators:
            indicators["process_has_afd_socket_handles"] = True

        for t in susp_process:
            if t["pid"] == pid:
                reasons = t.get("reasons", [])
                if "Unknown start address appears user/private-space" in reasons:
                    analysis_ioc[pid].append(f"Unknown Start Path and user/private-space address thread")
                if "unknwon_start_path_and_user_private_space_address_thread" not in indicators:
                    indicators["unknwon_start_path_and_user_private_space_address_thread"] = True
        if debug:
            print(f"[PID {pid}] AFD socket handles found: {len(afd_entries)}")
            for line in afd_entries:
                print(line)        

    return susp_process_with_sockets


def dump_suspicious_processes_with_sockets(
    dump_file: str,
    susp_process_with_sockets: List[Dict[str, Any]],
    dumps_dir: str = "dumps",
    debug: bool = False,
) -> List[Dict[str, Any]]:
    """
    Create process memory dumps for PIDs found in `susp_process_with_sockets`.

    Steps:
    - Ensure `dumps_dir` exists.
        - Remove old dump files for each target PID from `dumps_dir`.
    - For each unique PID in `susp_process_with_sockets`, run:
            `vol -f <dump_file> windows.malfind --pid <pid> --dump`

    Returns:
        List of per-PID results with command status and generated files.
    """
    dump_results: List[Dict[str, Any]] = []
    dumps_dir_abs = os.path.abspath(dumps_dir)
    os.makedirs(dumps_dir_abs, exist_ok=True)

    if not susp_process_with_sockets:
        return dump_results

    seen_pids: Set[int] = set()

    for entry in susp_process_with_sockets:
        pid = entry.get("pid")
        if not isinstance(pid, int) or pid in seen_pids:
            continue
        seen_pids.add(pid)

        pid_tag = f"pid.{pid}."
        deleted_old_files: List[str] = []
        for existing_name in os.listdir(dumps_dir_abs):
            existing_path = os.path.join(dumps_dir_abs, existing_name)
            if not os.path.isfile(existing_path):
                continue
            if pid_tag in existing_name:
                try:
                    os.remove(existing_path)
                    deleted_old_files.append(existing_name)
                except OSError:
                    pass

        if debug and deleted_old_files:
            print(f"[PID {pid}] deleted old dump files: {deleted_old_files}")

        before_files = set(os.listdir(dumps_dir_abs))

        result = subprocess.run(
            [
                "vol",
                "-o",
                dumps_dir_abs,
                "-f",
                dump_file,
                "windows.malfind",
                "--pid",
                str(pid),
                "--dump",
            ],
            capture_output=True,
            text=True,
        )

        after_files = set(os.listdir(dumps_dir_abs))
        created_files = sorted(after_files - before_files)

        pid_result = {
            "pid": pid,
            "deleted_old_files": deleted_old_files,
            "returncode": result.returncode,
            "created_files": created_files,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        dump_results.append(pid_result)

        if debug:
            print(f"[PID {pid}] malfind dump return code: {result.returncode}")
            if created_files:
                print(f"[PID {pid}] created dump files: {created_files}")
            elif result.returncode == 0:
                print(f"[PID {pid}] command succeeded but no new files detected in {dumps_dir_abs}")
            if result.stderr:
                print(result.stderr)

    return dump_results


def delete_all_files_in_dumps_directory(dumps_dir: str = "dumps", debug: bool = False) -> List[str]:
    """Delete all files under `dumps_dir` (recursively) and return deleted paths."""
    deleted_files: List[str] = []
    dumps_dir_abs = os.path.abspath(dumps_dir)

    if not os.path.isdir(dumps_dir_abs):
        return deleted_files

    for root, _, files in os.walk(dumps_dir_abs):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                os.remove(file_path)
                deleted_files.append(file_path)
            except OSError:
                continue

    if debug and deleted_files:
        print(f"[DUMPS CLEANUP] deleted {len(deleted_files)} files from {dumps_dir_abs}")

    return deleted_files


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

            print(processed_result)

            if processed_result:

                if collect_process_info:
                    process_information[pid]["YARAStrings"].extend(processed_result)

                message = "suspicious string match in memory"
                if message.replace(" ", "_") not in indicators:
                    indicators[message.replace(" ", "_")] = True
                if message not in analysis_ioc[pid]:
                    analysis_ioc[pid].append(message)


def extract_windows_yara_match_from_process_dumps(
    analysis_ioc,
    indicators,
    strings_of_interest=None,
    dumps_dir: str = "dumps",
    yara_rule_file: Optional[str] = None,
    debug: bool = False,
    process_information=None,
    collect_process_info: bool = False,
):
    """
    Scan Windows process dump files in `dumps_dir` with YARA and update IoCs/indicators.

    Behavior (similar intent to extract_string_match_from_dump):
    - If `yara_rule_file` is provided, compile rules from file.
    - Else compile an inline rule from `strings_of_interest`.
    - Scan each dump file and attach matches to PID inferred from filename (`pid.<PID>.*`).
    """
    print("Extracting YARA Matches from Windows Process Dumps...")

    if not os.path.isdir(dumps_dir):
        if debug:
            print(f"Dumps directory not found: {dumps_dir}")
        return []

    try:
        import yara
    except ImportError:
        raise RuntimeError("yara-python is not installed in the active environment.")

    rules = None
    if yara_rule_file:
        rules = yara.compile(filepath=yara_rule_file)
    else:
        deduped_strings: List[str] = []
        seen_strings: Set[str] = set()
        for value in (strings_of_interest or []):
            value_str = str(value).strip()
            if not value_str or value_str in seen_strings:
                continue
            seen_strings.add(value_str)
            deduped_strings.append(value_str)
        strings_of_interest = deduped_strings
        if not strings_of_interest:
            if debug:
                print("No strings_of_interest provided for inline YARA rule compilation")
            return []

        def _escape_for_yara(value: str) -> str:
            return value.replace("\\", "\\\\").replace('"', '\\"')

        def _is_hex_wildcard_pattern(value: str) -> bool:
            tokens = [token for token in value.strip().split() if token]
            if not tokens:
                return False
            return all(re.fullmatch(r"(?:[0-9A-Fa-f]{2}|\?\?)", token) for token in tokens)

        string_lines = []
        identifier_to_pattern: Dict[str, str] = {}
        for index, value in enumerate(strings_of_interest):
            value_str = str(value).strip()
            identifier = f"$s{index}"
            identifier_to_pattern[identifier] = value_str
            if _is_hex_wildcard_pattern(value_str):
                hex_pattern = " ".join(token.upper() if token != "??" else "??" for token in value_str.split())
                string_lines.append(f"    {identifier} = {{ {hex_pattern} }}")
            else:
                escaped = _escape_for_yara(value_str)
                string_lines.append(f'    {identifier} = "{escaped}" nocase ascii wide')

        rule_source = (
            "rule InlineSuspiciousStrings {\n"
            "  strings:\n"
            + "\n".join(string_lines)
            + "\n  condition:\n"
            "    any of them\n"
            "}"
        )
        rules = yara.compile(source=rule_source)

    dump_files = [
        os.path.join(dumps_dir, name)
        for name in os.listdir(dumps_dir)
        if os.path.isfile(os.path.join(dumps_dir, name)) and name.endswith(".dmp")
    ]

    scan_results = []
    if yara_rule_file:
        identifier_to_pattern = {}
    for dump_path in dump_files:
        file_name = os.path.basename(dump_path)
        pid_match = re.search(r"pid\.(\d+)\.", file_name)
        pid = int(pid_match.group(1)) if pid_match else None

        try:
            matches = rules.match(dump_path)
        except Exception as error:
            if debug:
                print(f"YARA scan failed for {dump_path}: {error}")
            continue

        if not matches:
            continue

        matched_rules = [m.rule for m in matches]
        matched_strings = []
        matched_seen = set()
        for match in matches:
            for string_match in getattr(match, "strings", []):
                try:
                    mapped_pattern = None
                    if isinstance(string_match, tuple) and len(string_match) >= 3:
                        tuple_identifier = string_match[1] if len(string_match) > 1 else None
                        if isinstance(tuple_identifier, str):
                            mapped_pattern = identifier_to_pattern.get(tuple_identifier)
                    else:
                        identifier = getattr(string_match, "identifier", None)
                        if isinstance(identifier, str):
                            mapped_pattern = identifier_to_pattern.get(identifier)

                    if mapped_pattern and mapped_pattern not in matched_seen:
                        matched_seen.add(mapped_pattern)
                        matched_strings.append(mapped_pattern)
                except Exception:
                    continue

        result_item = {
            "pid": pid,
            "dump_file": dump_path,
            "matched_rules": matched_rules,
            "matched_strings": list(set(filter(None, matched_strings))),
        }
        scan_results.append(result_item)

        if isinstance(pid, int):
            if pid not in analysis_ioc:
                analysis_ioc[pid] = []

            message = "suspicious string match in memory"
            if message not in analysis_ioc[pid]:
                analysis_ioc[pid].append(message)

            if collect_process_info:
                if process_information is None:
                    process_information = {}
                if pid not in process_information:
                    process_information[pid] = {}
                if "YARAStrings" not in process_information[pid]:
                    process_information[pid]["YARAStrings"] = []
                process_information[pid]["YARAStrings"].append(result_item)

        indicators["suspicious_string_match_in_memory"] = True

        if debug:
            print(f"[YARA DUMP MATCH] pid={pid} file={dump_path} rules={matched_rules}")

    return scan_results


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


def _canonical_token_from_path(path: str, record_non_sockets: bool = True) -> Optional[str]:
    if not path:
        return None

    m = socket_path_re.search(path)
    if m:
        return f"socket:[{m.group('sid')}]"

    m = pipe_path_re.search(path)
    if m:
        return f"pipe:[{m.group('pid')}]"

    m = anon_inode_re.search(path)
    if m:
        return f"anon_inode:[{m.group('aid')}]"

    m = pty_re.match(path)
    if m:
        return f"pty:{path}"

    m = tty_re.match(path)
    if m:
        return f"tty:{path}"

    if devnull_re.match(path):
        return "devnull:/dev/null"

    if record_non_sockets and path.startswith("/"):
        return f"file:{path}"

    return None



def parse_fd_redirections(text: str) -> Dict[str, Optional[str]]:
    """
    Parse Volatility/LSOF-like FD table text using the provided lsof_pattern first.
    Falls back to a simpler regex if the full set of columns isn’t present.

    Returns:
      { 'STDIN': canonical_token_or_none, 'STDOUT': canonical_token_or_none, 'STDERR': canonical_token_or_none }
    """
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    result: Dict[str, Optional[str]] = {name: None for name in FD_TO_NAME.values()}
    if not lines:
        return result

    # Find the header (must include 'PID', 'FD', 'Path')
    header_idx = None
    for i, ln in enumerate(lines):
        if ("PID" in ln) and ("FD" in ln) and ("Path" in ln):
            header_idx = i
            break

    data_lines = lines[header_idx + 1:] if header_idx is not None else lines

    for ln in data_lines:
        m = lsof_pattern.match(ln)
        # if not m:
        #     # Try fallback if the line doesn’t have all the columns
        #     m = fallback_line_re.match(ln)
        #     if not m:
        #         continue
        if not m:
            continue

        gd = m.groupdict()
        fd = gd.get("fd")
        path = gd.get("path")

        if fd not in FD_TO_NAME:
            continue

        std_name = FD_TO_NAME[fd]
        token = _canonical_token_from_path(path, record_non_sockets=True)

        if token:
            result[std_name] = token

    return result




def _kind_and_id(token: Optional[str]) -> Tuple[str, Optional[str]]:
    """
    Decode canonical token into (kind, id_or_path_for_display).
    kind in {'SOCKET','PIPE','ANON_INODE','PTY','TTY','DEVNULL','FILE','UNKNOWN'}
    """
    if not token:
        return ("UNKNOWN", None)

    if token.startswith("socket:["):
        return ("SOCKET", token)
    if token.startswith("pipe:["):
        return ("PIPE", token)
    if token.startswith("anon_inode:["):
        return ("ANON_INODE", token)
    if token.startswith("pty:"):
        return ("PTY", token.split("pty:", 1)[1])
    if token.startswith("tty:"):
        return ("TTY", token.split("tty:", 1)[1])
    if token.startswith("devnull:"):
        return ("DEVNULL", "/dev/null")
    if token.startswith("file:"):
        return ("FILE", token.split("file:", 1)[1])

    return ("UNKNOWN", token)


def normalize_lsof_output(fd_map: Dict[str, Optional[str]], include_socket_id: bool = False) -> str:
    """
    Build normalized statements based on the mapping.
    Extended to handle PTY/TTY/PIPE/ANON_INODE/DEVNULL/FILE in addition to SOCKET.

    If include_socket_id=True, include the canonical tokens for sockets (and, for clarity,
    we also include identifiers/paths for other kinds).
    """
    stdin = fd_map.get("STDIN")
    stdout = fd_map.get("STDOUT")
    stderr = fd_map.get("STDERR")

    def fmt(kind: str, ident: Optional[str]) -> str:
        """
        Produce a compact phrase for the target, honoring include_socket_id for SOCKET.
        For non-socket kinds, include identifiers/paths when available.
        """
        if kind == "SOCKET":
            return "socket FD" if not include_socket_id or not ident else ident
        if kind == "PIPE":
            return "pipe" if not include_socket_id or not ident else ident
        if kind == "ANON_INODE":
            return "anonymous inode" if not include_socket_id or not ident else ident
        if kind == "PTY":
            return "PTY" if not include_socket_id or not ident else f"PTY ({ident})"
        if kind == "TTY":
            return "TTY" if not include_socket_id or not ident else f"TTY ({ident})"
        if kind == "DEVNULL":
            return "/dev/null"
        if kind == "FILE":
            return "file" if not include_socket_id or not ident else f"file ({ident})"
        return "unknown target"

    # Decode kinds and identifiers
    sin_kind, sin_id = _kind_and_id(stdin)
    sout_kind, sout_id = _kind_and_id(stdout)
    serr_kind, serr_id = _kind_and_id(stderr)

    lines = []

    # All three redirected to the same kind and same identifier?
    if (
        stdin and stdout and stderr and
        sin_kind == sout_kind == serr_kind and
        sin_id == sout_id == serr_id
    ):
        lines.append(f"STDIN STDOUT STDERR redirected to same {fmt(sin_kind, sin_id)}")
        return "\n".join(lines)

    # Helper to add pair messages
    used = set()

    def add_pair(a_name: str, b_name: str, a_token: Optional[str], b_token: Optional[str]):
        a_kind, a_id = _kind_and_id(a_token)
        b_kind, b_id = _kind_and_id(b_token)
        if a_token and b_token and a_kind == b_kind and a_id == b_id:
            lines.append(f"{a_name} {b_name} redirected to same {fmt(a_kind, a_id)}")
            used.update({a_name, b_name})

    add_pair("STDIN", "STDOUT", stdin, stdout)
    add_pair("STDIN", "STDERR", stdin, stderr)
    add_pair("STDOUT", "STDERR", stdout, stderr)

    # Individual messages for any remaining single redirections not covered above
    for name, token in [("STDIN", stdin), ("STDOUT", stdout), ("STDERR", stderr)]:
        if token and name not in used:
            kind, ident = _kind_and_id(token)
            lines.append(f"{name} redirected to {fmt(kind, ident)}")

    # If nothing detected, return empty string
    if not lines:
        return ""

    return "\n".join(lines)


def extract_socket_redirections_from_lsof_output(
    dump_file,
    analysis_ioc,
    indicators,
    debug=False,
    process_information=None,
    collect_process_info=False,
    include_socket_id: bool = False
) -> str:
    """
    Given the lsof/volatility output (queried per PID), parse and extract
    STDIN/STDOUT/STDERR redirections, returning normalized statements (joined for all pids).
    """
    all_statements = []

    for pid in list(analysis_ioc.keys()):
        if collect_process_info:
            if process_information is None:
                process_information = dict()
            if pid not in process_information:
                process_information[pid] = dict()
            if "SocketRedirections" not in process_information[pid]:
                process_information[pid]["SocketRedirections"] = []

        # You likely have this helper already; keeping your call as-is:
        lsof_output = execute_system_command(f"vol -f {dump_file} linux.lsof --pid {pid}")

        if debug:
            print(lsof_output)

        fd_map = parse_fd_redirections(lsof_output)
        normalized_statements = normalize_lsof_output(fd_map, include_socket_id=include_socket_id)

        # Store for per-process info, if requested
        if collect_process_info and normalized_statements:
            process_information[pid]["SocketRedirections"].append(fd_map)

        # Track indicators (dedup)
        key = normalized_statements.replace(" ", "_")
        if normalized_statements and key not in indicators:
            indicators[key] = True

        if normalized_statements and normalized_statements not in analysis_ioc[pid]:
            analysis_ioc[pid].append(normalized_statements)

        if normalized_statements:
            all_statements.append(f"[PID {pid}] {normalized_statements}")

    # Return combined statements across all processed PIDs
    return "\n".join(all_statements)
