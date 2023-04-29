#!/usr/bin/env python3
import argparse
from datetime import datetime, timedelta
import multiprocessing as mp
import subprocess
import time


def curl_req():
    subprocess.run('sleep 5'.split())


def main_loop(loop_time, interval: float):
    start_ts = datetime.now()
    stop_ts = (start_ts + timedelta(seconds=loop_time)
               if loop_time is not None else None)
    delta_timeout = timedelta(seconds=3)
    print('[{}] start'.format(start_ts))
    tasks = []
    try:
        while stop_ts is None or datetime.now() < stop_ts:
            now = datetime.now()
            # stop and clear outdated tasks
            while len(tasks) > 0:
                t = tasks[0]
                if not t[1].is_alive():
                    del tasks[0]
                    continue
                if t[0] < now:
                    t[1].terminate()
                    del tasks[0]
                    continue
            # add new tasks
            print('[{}] make reqests'.format(now))
            p = mp.Process(
                target=subprocess.run,
                args=('curl -sk https://10.0.1.1 -o /dev/null'.split(),))
            tasks.append((now+delta_timeout, p))
            p.start()
            p = mp.Process(
                target=subprocess.run,
                args=(('wget https://10.0.1.1 -o /dev/null'
                       ' --no-check-certificate').split(),))
            tasks.append((now+delta_timeout, p))
            p.start()
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    while len(tasks) > 0:
        t = tasks[0]
        if t[1].is_alive():
            t[1].kill()
        del tasks[0]
    now = datetime.now()
    print('[{}] exit request loop'.format(now))


def main():
    pser = argparse.ArgumentParser()
    pser.add_argument('--loop-time', type=float)
    pser.add_argument('--interval', type=float, default=3)
    args = pser.parse_args()
    main_loop(**vars(args))


if __name__ == '__main__':
    main()
