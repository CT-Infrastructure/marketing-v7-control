"""Explicit, bounded TEST-NET probe for the trusted isolated runner only.

Not imported or executed by normal unit tests. A deny observation for one address
is not proof of complete network isolation, DNS controls, or production safety.
"""
import argparse
import errno
import json
import os
import socket


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe-test-net',action='store_true')
    args=parser.parse_args()
    if not args.probe_test_net or os.environ.get('F07_NETWORK_NAMESPACE_EXPECTED')!='1':
        print(json.dumps({'status':'NOT_RUN','reason':'explicit isolated-runner opt-in required'}))
        return 2
    # Literal documentation address, no resolver and no data transmission.
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        try:
            connection.connect(('192.0.2.1',9))
        except OSError as exc:
            if exc.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EACCES,errno.EPERM):
                print(json.dumps({'status':'DENY_OBSERVED','target':'192.0.2.1:9','errno':exc.errno,'scope':'one TCP TEST-NET connection only'}))
                return 0
            print(json.dumps({'status':'INCONCLUSIVE','errno':exc.errno,'scope':'TEST-NET only'}))
            return 2
        print(json.dumps({'status':'DENY_FAILED','target':'192.0.2.1:9'}))
        return 1

if __name__=='__main__':
    raise SystemExit(main())
