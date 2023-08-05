import os
import subprocess
import re
from pwn import *

t_file = null
t_lib = null
t_arch = null
t_patch = null
t_path = "/home/t1d/tools"
t_pwnlib = null
t_pwnfile = null

def tset(my_file):
    global t_file, tlib, tarch, t_patch
    t_file = my_file
    t_lib = tlibc()
    t_arch = tarch()
    if t_lib and t_arch:
        t_patch = f"{t_lib}_{t_arch}"
        
def tbegin():
    global t_pwnfile, t_pwnlib
    t_pwnfile = ELF(f"{t_file}")
    t_pwnlib = t_pwnfile.libc
        
def search_folder(root_folder, target_folder):
    target_path = os.path.join(root_folder, target_folder)
    return os.path.exists(target_path)
            
def find_so_files(directory):
    so_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.so.6'):
                so_files.append(os.path.join(root, file))
    if not so_files:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.so'):
                    so_files.append(os.path.join(root, file))
    return so_files

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        stdout_output = result.stdout.strip()
        stderr_output = result.stderr.strip()
        return stdout_output, stderr_output
    except subprocess.CalledProcessError as e:
        log.error(f"ERROR: {e}")
        return None, None

def tlibc():
    current_directory = os.getcwd()
    so_files = find_so_files(current_directory)

    if so_files:
        for so_file in so_files:
            command = f"strings {so_file} | grep 'GLIBC'"
            stdout, stderr = execute_command(command)
            if stdout:
                version_match = re.search(r'(\d+\.\d+\-\S+)(?=\))', stdout)
                if version_match:
                    version_info = version_match.group()
                    log.success(f"Glibc version: {version_info}")
                    return version_info
                else:
                    log.warning(f"Version information for the file {so_file} was not found.")
                    return null
    else:
        log.warning("The .so or .so.6 file was not found.")
        return null
        
def tarch():
    if t_file == null:
        log.error("Please configure the file first!")
        return null
    command = f"checksec {t_file}"
    stdout, stderr = execute_command(command)
    if stderr:
        arch_match = re.search(r'Arch:\s+(amd64|i386)', stderr)
        if arch_match:
            arch_info = arch_match.group(1)
            log.success(f"Arch: {arch_info}")
            return arch_info
        else:
            log.error("Architecture information not found.")
            return null
    else:
        log.error("The file was not found.")
        return null
    
def tpatchelf(*args):
    if t_patch == null:
        log.warning(f"tset at first!")
        return
    if os.path.exists(f"{t_path}/glibc-all-in-one/libs/{t_patch}"):
        pass
    else:
        log.warning(f"Please download the corresponding version of the glibc package first!")
        return
    command = f"patchelf --replace-needed libc.so.6 {t_path}/glibc-all-in-one/libs/{t_patch}/libc.so.6 {t_file}"
    stdout, stderr = execute_command(command)
    if stderr:
        log.error(f"Patchelf failed for libc.so.6 file!")
        return
    if "amd64" in t_patch:
        command = f"patchelf --set-interpreter {t_path}/glibc-all-in-one/libs/{t_patch}/ld-linux-x86-64.so.2 {t_file}"
        stdout, stderr = execute_command(command)
    else:
        command = f"patchelf --set-interpreter {t_path}/glibc-all-in-one/libs/{t_patch}/ld-linux.so.2 {t_file}"
        stdout, stderr = execute_command(command)
    if stderr:
        log.error(f"Patchelf failed for *.so.2 file!")
        return   
    if args:
        for arg in args:
            command = f"patchelf --add-needed ./{arg} {t_file}"
            stdout, stderr = execute_command(command)
            if stderr:
                log.error(f"patchelf failed for {arg} file!")
                return
    log.success(f"Patchelf successfully!")
