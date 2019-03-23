#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

from joblib import Parallel, delayed
import multiprocessing

map_dir = Path(sys.argv[1])
dest_dir = Path(sys.argv[2])

def main() -> None:
    if not map_dir.is_dir() or not dest_dir.is_dir():
        sys.stderr.write('error: map_dir and dest_dir must be directories')
        sys.exit(100)

    num_cores = multiprocessing.cpu_count()

    def process_mubin(mubinp: Path) -> None:
        rel_path = mubinp.relative_to(map_dir)
        print(rel_path)

        dest_path = dest_dir / rel_path
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_call(['byml_to_yml', mubinp, dest_path.with_suffix('.yml')])

    Parallel(n_jobs=num_cores)(delayed(process_mubin)(mubinp) for mubinp in map_dir.glob('**/*.smubin'))

if __name__ == '__main__':
    main()
