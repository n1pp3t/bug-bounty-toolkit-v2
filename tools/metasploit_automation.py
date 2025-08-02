import subprocess

def run_metasploit_module(module, options):
    """
    Runs a Metasploit module with the given options.
    """
    # This is a placeholder for a real implementation.
    # In a real-world scenario, you would use the msfrpc-client library or similar.
    print(f"[*] Running Metasploit module {module} with options: {options}")
    cmd = ["msfconsole", "-q", "-x", f"use {module};"]
    for key, value in options.items():
        cmd.append(f"set {key} {value};")
    cmd.append("run;")
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Metasploit Automation Tool")
    parser.add_argument("module", help="The Metasploit module to run.")
    # Add arguments for common options like RHOSTS, LHOST, LPORT, etc.
    parser.add_argument("--rhosts", help="The target host(s).")
    parser.add_argument("--lhost", help="The listening host.")
    parser.add_argument("--lport", help="The listening port.")
    args = parser.parse_args()
    options = {}
    if args.rhosts:
        options["RHOSTS"] = args.rhosts
    if args.lhost:
        options["LHOST"] = args.lhost
    if args.lport:
        options["LPORT"] = args.lport
    
    output = run_metasploit_module(args.module, options)
    print(output)
