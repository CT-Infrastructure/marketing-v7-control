"""File/stdout entry point for sanitized snapshots. Never opens a controller DB."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import telemetry


def write_reports(directory,report):
    path=Path(directory)
    if not path.is_dir() or path.is_symlink():
        raise ValueError('existing nonsymlink output directory required')
    contents={'agents.json':telemetry.canonical(report)+'\n','agents.prom':telemetry.prometheus(report)}
    for name,body in contents.items():
        temp=None
        try:
            with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path,prefix='.f17-',delete=False) as stream:
                temp=Path(stream.name);stream.write(body)
            os.replace(temp,path/name)
        finally:
            if temp is not None and temp.exists():temp.unlink()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot')
    parser.add_argument('--now',required=True)
    parser.add_argument('--previous-cursor')
    parser.add_argument('--output-dir')
    parser.add_argument('--prometheus',action='store_true')
    args=parser.parse_args()
    try:
        snapshot=telemetry.read_snapshot(args.snapshot)
        previous=telemetry.read_snapshot(args.previous_cursor) if args.previous_cursor else None
        report=telemetry.render(snapshot,args.now,previous)
        if args.output_dir:write_reports(args.output_dir,report)
        print(telemetry.prometheus(report) if args.prometheus else telemetry.canonical(report))
        return 0
    except (ValueError,TypeError,KeyError,OSError,OverflowError):
        # Never echo input values, file paths, exception text or raw provider records.
        print(json.dumps({'status':'INVALID_SNAPSHOT','admission_signal':False,'dispatch_authorized':False}))
        return 2

if __name__=='__main__':
    raise SystemExit(main())
