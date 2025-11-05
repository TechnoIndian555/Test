import ipaddress, threading, requests, urllib3, time, sys, os

from concurrent.futures import as_completed, ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


CC = '\033[0m'  # CLEAR COLOR
CL = '\033[2K '  # CLEAR LINE


# ————— 𝐥𝐨𝐠𝐠𝐞𝐫 𝐏𝐫𝐨𝐠𝐫𝐞𝐬𝐬 𝐋𝐢𝐧𝐞 —————
def logger(progress_line):
    
    try:
        columns, _ = os.get_terminal_size()
    except OSError:
        columns = 80

    if len(progress_line) > columns:
        progress_line = progress_line[:columns - 3] + '...'

    sys.stdout.write(f'{CL}{CC}{progress_line}{CC}\r')
    sys.stdout.flush()


# ————— 𝐢𝐬𝐂𝐈𝐃𝐑 —————
def isCIDR(CIDR):

    try:
        IP_Range = ipaddress.ip_network(CIDR, strict=False)

        return [str(IP) for IP in IP_Range]

    except ValueError as e:
        print(f'\n[ ERROR ] Invalid CIDR / HOST : {e} ✘\n')

        print(f'\n[ INFO ] CIDR 127.0.0.0/24 OR Multi CIDR 127.0.0.0/24 104.0.0.0/24\n')

        return []


# ————— 𝐂𝐇𝐄𝐂𝐊 𝐇𝐓𝐓𝐏'𝐬 𝐑𝐄𝐒𝐏𝐎𝐍𝐒𝐄 —————
def isRequest(HOST, PORT):

    PROTOCOL = 'https' if PORT == "443" else 'http'

    URL = f"{PROTOCOL}://{HOST}"

    for attempt in range(2):
        try:
            response = requests.request('HEAD', URL, timeout=5, verify=False, allow_redirects=False)

            SERVER = response.headers.get('server', '')

            return HOST, SERVER

        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:

            #print(f"{CL}{CC}[{type(e).__name__}] : {HOST}{CC}\r")

            if attempt == 0:
                time.sleep(1)
                continue

            return None

        except requests.exceptions.RequestException as e:

            #print(f"{CL}{CC}[!] {HOST} : {type(e).__name__}{CC}\r")

            return None


# ————— 𝐈𝐏 𝐒𝐂𝐀𝐍𝐍𝐄𝐑 —————
def IP_SCANNER(HOSTS, PORTS):

    Total_HOST = len(HOSTS) * len(PORTS)

    Scanned_HOST = Respond_HOST = 0

    RESPOND = {}

    with ThreadPoolExecutor(max_workers=100) as executor:

        is_Request = {}

        for HOST in HOSTS:
            for PORT in PORTS:
                isHOST = executor.submit(isRequest, HOST, PORT)

                is_Request[isHOST] = (HOST, PORT)

        for isHOST in as_completed(is_Request):
            Scanned_HOST += 1
            CURRENT_HOST, _ = is_Request[isHOST]
            RESULT = isHOST.result()

            if RESULT:

                Respond_HOST += 1
                
                HOST, SERVER = RESULT

                RESPOND[HOST] = SERVER

                print(f"\r{CL}[+] {HOST} → {SERVER}")

            progress_line = (
                f"- PC - {(Scanned_HOST / Total_HOST) * 100:.2f}% "
                f"- SN - {Scanned_HOST}/{Total_HOST} "
                f"- RS - {Respond_HOST} "
                f"- {CURRENT_HOST}"
            )

            logger(progress_line)


    # ————— 𝐑𝐄𝐒𝐏𝐎𝐍𝐒𝐄 𝐎𝐔𝐓𝐏𝐔𝐓 —————

    OUTPUT_PATH = "IPs.txt"

    if RESPOND:
        with open(OUTPUT_PATH, 'a') as file:

            file.write(f'\n{"# IP Address":<16}  |  {"Server"}\n')
            file.write('-' * 40 + '\n')

            for HOST, SERVER in RESPOND.items():
                file.write(f"{HOST:<16}  |  {SERVER}\n")

        print(f"\n[✓] Results Saved ➢ {OUTPUT_PATH}\n")


# ————— 𝐄𝐱𝐞𝐜𝐮𝐭𝐞 𝐒𝐜𝐫𝐢𝐩𝐭 —————
if __name__ == '__main__':

    CIDR = "0.0.0.0/0"

    HOSTS = isCIDR(CIDR)

    PORTS = ["80"]

    IP_SCANNER(HOSTS, PORTS)