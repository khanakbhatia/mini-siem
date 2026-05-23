import time
from datetime import datetime

LOG = '../../data/sample_auth.log' # run from src/tests/
IP = '192.0.2.23'

TEMPLATE = '{ts} myhost sshd[12345]: Failed password for invalid user admin from {ip} port {port} ssh2\n'

if __name__ == '__main__':
    with open(LOG, 'a') as f:
        for i in range(8):
            ts = datetime.now().strftime('%b %e %H:%M:%S')
            f.write(TEMPLATE.format(ts=ts, ip=IP, port=55000 + i))
            f.flush()
            time.sleep(3) # 3 seconds between attempts