# watcher (C port)

C port of https://github.com/f1vefour/Watcher/blob/master/watcher.py using
only the C standard library plus glibc's POSIX/Linux headers (no third-party
libraries -- `sys/inotify.h` in place of `pyinotify`).

## Build

    gcc -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -o watcher watcher.c

## Usage

    ./watcher [-c /path/to/watcher.ini] {start|stop|restart|status|debug}

Default config search path (no `-c`): `/etc/watcher.ini`, then `~/.watcher.ini`.

See `watcher.ini` for the config format and config folder for examples -- same keys 
as the Python original: `watch`, `events`, `recursive`, `autoadd`, `excluded`, `command`,
plus `logfile`/`pidfile` in `[DEFAULT]`.

Command template variables: `$watched`, `$filename`, `$tflags`, `$nflags`,
`$cookie` -- same as the original, shell-quoted the same way.

Run `debug` mode first (foreground, no fork) to confirm your config works
before using `start` to daemonize.
