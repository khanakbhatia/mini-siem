import time
from datetime import datetime
from pathlib import Path

LOG = Path(__file__).resolve().parents[2] / 'data' / 'sample_auth.log'
IP = '192.0.2.23'

TEMPLATE = '{ts} myhost sshd[12345]: Failed password for invalid user admin from {ip} port {port} ssh2\n'

if __name__ == '__main__':
    with LOG.open('a', encoding='utf-8') as f:
        for i in range(8):
            ts = datetime.now().strftime('%b %e %H:%M:%S')
            f.write(TEMPLATE.format(ts=ts, ip=IP, port=55000 + i))
            f.flush()
            time.sleep(3) # 3 seconds between attempts
