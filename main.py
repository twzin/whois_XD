import subprocess, json, sys, re, platform, time, os, argparse


def args():
    parser = argparse.ArgumentParser(description="JONAS WHOIS")
    # group = parser.add_mutually_exclusive_group()
    parser.add_argument('-d', '--domain', type=str, help='Domain to whois')
    parser.add_argument('-o', '--output', type=str, default=None, help='Output file')
    return parser.parse_args()

def jonas(domain_name, output_file):

    if platform.system() == "Windows":
        time.sleep(2)
        print("[-] No whois on Windows")
        time.sleep(2)
        sys.exit(1)

    regex = re.search(r"^(?!-)[A-Za-z]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", domain_name)

    if regex:
        try:
            ping = subprocess.run(["ping", "-c", "4", domain_name], capture_output=True, text=True)
            reacheble = "0% packet loss" in ping.stdout
            if reacheble:
                print("[+] Reacheble!\n")
            else:
                print("[-] Domain not reacheble :(\n")
                time.sleep(1)
                sys.exit(1)
        except subprocess.TimeoutExpired:
            print("[-] Command Timed Out\n")

        try: 
            whois = subprocess.run(["whois", domain_name], capture_output=True, text=True)
            whois_data = {}
            for line in whois.stdout.splitlines():
                for field in ["owner:", "Registrar:", "Creation Date", "Expiry Date:"]:
                    if line.startswith(field):
                        whois_data[field] = line.split(":", 1)[-1].strip()
        except Exception as e:
            print(f"Error ocurred: {e}\n")

        report = {
            "domain": domain_name,
            "reachable": reacheble,
            "whois": whois_data
        }
        
        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(json.dump(report, f, indent=3))
                print(f"[+] Report saved to {output_file}")
            except:
                pass
        else:
            print(json.dumps(report, indent=3))


    else: 
        print("[-] Invalid Domain\n")
        time.sleep(2)
        sys.exit(1)

if __name__ == "__main__":
    args = args()


    if not args.domain:
        sys.exit(1)
    jonas(args.domain, args.output)
