"""File/stdout entry point for sanitized snapshots. Never opens a controller DB."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import telemetry


def invalidate_reports(directory):
    path=Path(directory)
    if not path.is_dir() or path.is_symlink():
        raise ValueError('existing nonsymlink output directory required')
    errors=[]
    for name in ('agents.json','agents.prom'):
        try:(path/name).unlink(missing_ok=True)
        except OSError as error:errors.append(error)
    if errors:raise OSError('could not invalidate unavailable export')


def write_reports(directory,report):
    path=Path(directory)
    if not path.is_dir() or path.is_symlink():
        raise ValueError('existing nonsymlink output directory required')
    contents={'agents.json':telemetry.canonical(report)+'\n','agents.prom':telemetry.prometheus(report)}
    staged=[]
    try:
        for name,body in contents.items():
            with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path,prefix='.f17-',delete=False) as stream:
                temp=Path(stream.name);staged.append((temp,path/name))
                stream.write(body);stream.flush();os.fsync(stream.fileno())
        for temp,target in staged:os.replace(temp,target)
    except (OSError,ValueError):
        # Never leave a prior positive or mixed-generation report after a failed write.
        invalidate_reports(path)
        raise
    finally:
        for temp,_ in staged:
            if temp.exists():temp.unlink()


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
        # No input values, paths, exception text or provider records in diagnostics.
        report=telemetry.unavailable_report(args.now)
        if args.output_dir:
            try:write_reports(args.output_dir,report)
            except (ValueError,TypeError,KeyError,OSError,OverflowError):
                try:invalidate_reports(args.output_dir)
                except (ValueError,OSError):pass
        print(telemetry.prometheus(report) if args.prometheus else telemetry.canonical(report))
        return 2


if __name__=='__main__':
    raise SystemExit(main())
