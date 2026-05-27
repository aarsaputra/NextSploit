import os
import subprocess
import time
import requests
import signal

LAB_DIR = "/nextjs-vuln-lab"
NEXTSPLOIT_DIR = "/home/lota1337/python/NextSploit"

def run_test_for_lab(folder_name):
    print(f"\n=============================================")
    print(f"[*] Starting test for: {folder_name}")
    print(f"=============================================")
    
    lab_path = os.path.join(LAB_DIR, folder_name)
    
    # Ensure port 3000 is free
    print("[*] Clearing port 3000...")
    os.system("fuser -k 3000/tcp > /dev/null 2>&1")
    time.sleep(1)
    
    # Start Next.js dev server
    print(f"[*] Booting up Next.js server for {folder_name}...")
    server_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=lab_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    
    # Poll until server is ready
    server_ready = False
    for _ in range(60):
        try:
            res = requests.get("http://localhost:3000", timeout=2)
            if res.status_code in [200, 404, 500]:
                server_ready = True
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
        
    if not server_ready:
        print(f"[!] Server for {folder_name} failed to boot up in 60 seconds.")
        os.killpg(os.getpgid(server_proc.pid), signal.SIGTERM)
        return
        
    print(f"[+] Server is UP! Running NextSploit...")
    
    # Run NextSploit
    scan_proc = subprocess.run(
        ["python", "nextsploit.py", "-t", "http://localhost:3000", "--all"],
        cwd=NEXTSPLOIT_DIR,
        capture_output=True,
        text=True
    )
    
    output = scan_proc.stdout
    print(f"[*] NextSploit output length: {len(output)} bytes")
    
    # Save the output to a report file
    report_file = f"reports/auto_{folder_name}.log"
    with open(os.path.join(NEXTSPLOIT_DIR, report_file), "w") as f:
        f.write(output)
        
    # Quickly summarize what was found
    findings = []
    for line in output.split('\n'):
        if "FINDING:" in line:
            findings.append(line.strip())
            
    if findings:
        print(f"[+] Findings for {folder_name}:")
        for f in findings:
            print(f"    {f}")
    else:
        print(f"[-] No vulnerabilities found for {folder_name}.")
        
    print(f"[*] Shutting down {folder_name} server...")
    os.killpg(os.getpgid(server_proc.pid), signal.SIGTERM)
    server_proc.wait()
    time.sleep(2) # Give port 3000 a moment to clear


if __name__ == "__main__":
    folders = [f for f in os.listdir(LAB_DIR) if f.startswith("lab-") and os.path.isdir(os.path.join(LAB_DIR, f))]
    folders.sort()
    
    for folder in folders:
        run_test_for_lab(folder)
        
    print("\n[+] All automated tests completed. Check the reports folder!")
