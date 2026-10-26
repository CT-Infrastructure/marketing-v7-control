"""Explicit, bounded TEST-NET probe for the trusted isolated runner only.

Normal unit tests mock sockets completely. A denial during creation or setup is
not proof of route isolation; no single probe proves full network/DNS safety.
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
    phase='socket_creation'
    connected=False
    primary_error=None
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as connection:
            try:
                phase='timeout_setup'
                connection.settimeout(2)
                phase='connect'
                connection.connect(('192.0.2.1',9))
                connected=True
                phase='cleanup'
            except OSError as exc:
                # Preserve the operation result before __exit__ can replace it.
                primary_error=(exc,phase)
                raise
    except OSError as exc:
        # A successful connect cannot be relabelled denied by a later close error.
        if connected:
            print(json.dumps({'status':'DENY_FAILED','target':'192.0.2.1:9','phase':phase}))
            return 1
        if primary_error is not None:
            exc,phase=primary_error
        if phase!='cleanup' and exc.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EACCES,errno.EPERM):
            print(json.dumps({'status':'DENY_OBSERVED','target':'192.0.2.1:9','errno':exc.errno,'phase':phase,'scope':'one TCP TEST-NET probe only'}))
            return 0
        print(json.dumps({'status':'INCONCLUSIVE','errno':exc.errno,'phase':phase,'scope':'TEST-NET only'}))
        return 2
    print(json.dumps({'status':'DENY_FAILED','target':'192.0.2.1:9'}))
    return 1


if __name__=='__main__':
    raise SystemExit(main())
