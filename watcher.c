/*
 * watcher.c - C port of watcher.py (https://github.com/f1vefour/Watcher)
 * Ported by f1vefour 09/08/2026
 *
 * A daemon that watches specified files/folders for changes (via Linux's
 * inotify mechanism) and runs a shell command in response to those changes.
 * Configuration is read from an .ini file, same format as the original
 * Python daemon.
 *
 * Built using ONLY the C standard library plus the POSIX / Linux headers
 * that are part of glibc (unistd.h, sys/inotify.h, sys/stat.h, signal.h,
 * dirent.h, etc.) -- no third-party libraries (no libconfig, no libevent,
 * nothing fetched from pip/apt beyond what a base glibc install provides).
 *
 * Original Python used pyinotify + ConfigParser + argparse; here we talk
 * to the inotify(7) syscalls directly and hand-roll a small INI parser
 * and argument parser.
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -o watcher watcher.c
 *
 * Usage:
 *   watcher [-c /path/to/watcher.ini] {start|stop|restart|status|debug}
 *
 * Default config search path: /etc/watcher.ini, then ~/.watcher.ini
 *
 * Copyright (c) 2010 Greggory Hernandez (original Python watcher.py)
 * C port retains the same MIT license terms as the original project.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <limits.h>
#include <regex.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define MAX_SECTIONS      64
#define MAX_KEY_LEN       128
#define MAX_VAL_LEN       1024
#define MAX_LINE_LEN      2048
#define MAX_WATCHES_PER   4096   /* max directories watched per job (recursive) */
#define MAX_EXCLUDES      32
#define INOTIFY_BUF_LEN   (1024 * (sizeof(struct inotify_event) + NAME_MAX + 1))

/* ------------------------------------------------------------------ */
/* INI config structures                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    char key[MAX_KEY_LEN];
    char value[MAX_VAL_LEN];
} KeyValue;

typedef struct {
    char name[MAX_KEY_LEN];
    KeyValue kv[32];
    int kv_count;
} Section;

typedef struct {
    Section sections[MAX_SECTIONS];
    int section_count;
    /* DEFAULT section values (logfile, pidfile) */
    char logfile[PATH_MAX];
    char pidfile[PATH_MAX];
} Config;

/* ------------------------------------------------------------------ */
/* Per-job watch structure                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    char section[MAX_KEY_LEN];
    char folder[PATH_MAX];
    char command[MAX_VAL_LEN];
    uint32_t mask;
    int recursive;
    int autoadd;
    regex_t excl_regex[MAX_EXCLUDES];
    int excl_count;

    /* wd -> full path mapping for this job, so we can reconstruct
     * event.pathname the way pyinotify does */
    int wds[MAX_WATCHES_PER];
    char wd_paths[MAX_WATCHES_PER][PATH_MAX];
    int wd_count;
} Job;

static Job jobs[MAX_SECTIONS];
static int job_count = 0;
static int inotify_fd = -1;

static char g_pidfile[PATH_MAX] = "/var/run/watcher.pid";
static char g_logfile[PATH_MAX] = "/var/log/watcher.log";
static FILE *g_logfp = NULL;

static volatile sig_atomic_t g_terminate = 0;

/* ------------------------------------------------------------------ */
/* Logging (mirrors Python's log() which prefixes a timestamp)         */
/* ------------------------------------------------------------------ */

static void log_msg(const char *fmt, ...) {
    char timebuf[64];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tmv);

    FILE *out = g_logfp ? g_logfp : stdout;

    fprintf(out, "%s ", timebuf);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);

    fprintf(out, "\n");
    fflush(out);
}

/* ------------------------------------------------------------------ */
/* Trim helpers                                                        */
/* ------------------------------------------------------------------ */

static char *lstrip(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

static void rstrip(char *s) {
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

static char *strip(char *s) {
    s = lstrip(s);
    rstrip(s);
    return s;
}

/* ------------------------------------------------------------------ */
/* Minimal INI parser (supports [section], key = value, key: value,   */
/* '#' and ';' comments, blank lines). Good enough for watcher.ini     */
/* files, mirrors Python's ConfigParser behavior used here.            */
/* ------------------------------------------------------------------ */

static Section *find_or_add_section(Config *cfg, const char *name) {
    for (int i = 0; i < cfg->section_count; i++) {
        if (strcmp(cfg->sections[i].name, name) == 0)
            return &cfg->sections[i];
    }
    if (cfg->section_count >= MAX_SECTIONS) {
        fprintf(stderr, "Too many sections in config file (max %d)\n", MAX_SECTIONS);
        exit(4);
    }
    Section *sec = &cfg->sections[cfg->section_count++];
    memset(sec, 0, sizeof(*sec));
    snprintf(sec->name, sizeof(sec->name), "%s", name);
    return sec;
}

static void section_set(Section *sec, const char *key, const char *value) {
    for (int i = 0; i < sec->kv_count; i++) {
        if (strcasecmp(sec->kv[i].key, key) == 0) {
            snprintf(sec->kv[i].value, sizeof(sec->kv[i].value), "%s", value);
            return;
        }
    }
    if (sec->kv_count >= 32) {
        fprintf(stderr, "Too many keys in section [%s]\n", sec->name);
        exit(4);
    }
    snprintf(sec->kv[sec->kv_count].key, sizeof(sec->kv[sec->kv_count].key), "%s", key);
    snprintf(sec->kv[sec->kv_count].value, sizeof(sec->kv[sec->kv_count].value), "%s", value);
    sec->kv_count++;
}

static const char *section_get(Section *sec, const char *key, const char *def) {
    for (int i = 0; i < sec->kv_count; i++) {
        if (strcasecmp(sec->kv[i].key, key) == 0)
            return sec->kv[i].value;
    }
    return def;
}

/* Parse one ini file into cfg. Returns 1 on success, 0 if file couldn't
 * be opened. DEFAULT section values are copied into every other section
 * (ConfigParser semantics) at the time each section is finalized -- we
 * approximate that by merging DEFAULT into every section at lookup time
 * instead (simpler and behaviorally equivalent for our read-only use). */
static int parse_ini_file(const char *path, Config *cfg) {
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char line[MAX_LINE_LEN];
    Section *cur = find_or_add_section(cfg, "DEFAULT");

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        /* strip newline */
        size_t len = strlen(p);
        while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r')) {
            p[--len] = '\0';
        }
        p = strip(p);

        if (*p == '\0') continue;                 /* blank */
        if (*p == '#' || *p == ';') continue;      /* comment */

        if (*p == '[') {
            char *end = strchr(p, ']');
            if (!end) continue; /* malformed, skip */
            *end = '\0';
            char *name = strip(p + 1);
            cur = find_or_add_section(cfg, name);
            continue;
        }

        /* key = value  or  key: value */
        char *eq = strchr(p, '=');
        char *colon = strchr(p, ':');
        char *sep = NULL;
        if (eq && colon) sep = (eq < colon) ? eq : colon;
        else if (eq) sep = eq;
        else sep = colon;

        if (!sep) continue; /* malformed line, skip */

        *sep = '\0';
        char *key = strip(p);
        char *val = strip(sep + 1);
        section_set(cur, key, val);
    }

    fclose(fp);
    return 1;
}

/* Get a key's value for a section, falling back to DEFAULT section,
 * mirroring Python ConfigParser inheritance. Exits with an error if
 * required and missing. */
static const char *cfg_get(Config *cfg, Section *sec, const char *key, int required, const char *def) {
    const char *v = section_get(sec, key, NULL);
    if (!v) {
        Section *defsec = find_or_add_section(cfg, "DEFAULT");
        v = section_get(defsec, key, NULL);
    }
    if (!v) {
        if (required) {
            fprintf(stderr, "Config error: missing required key '%s' in section [%s]\n", key, sec->name);
            exit(4);
        }
        return def;
    }
    return v;
}

static int cfg_get_bool(Config *cfg, Section *sec, const char *key, int required, int def) {
    const char *v = cfg_get(cfg, sec, key, required, NULL);
    if (!v) return def;
    if (strcasecmp(v, "1") == 0 || strcasecmp(v, "true") == 0 ||
        strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0)
        return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Shell quoting -- mirrors Python's shellquote() helper:              */
/*   s -> "'" + s.replace("'", "'\\''") + "'"                          */
/* ------------------------------------------------------------------ */

static void shellquote(const char *s, char *out, size_t outlen) {
    size_t oi = 0;
    if (oi < outlen - 1) out[oi++] = '\'';
    for (const char *p = s; *p && oi < outlen - 5; p++) {
        if (*p == '\'') {
            /* '\'' */
            out[oi++] = '\'';
            out[oi++] = '\\';
            out[oi++] = '\'';
            out[oi++] = '\'';
        } else {
            out[oi++] = *p;
        }
    }
    if (oi < outlen - 1) out[oi++] = '\'';
    out[oi] = '\0';
}

/* ------------------------------------------------------------------ */
/* Template substitution -- mirrors Python string.Template with        */
/* $watched $filename $tflags $nflags $cookie substitutions.           */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    const char *value;
} TemplateVar;

static void template_substitute(const char *tmpl, TemplateVar *vars, int nvars,
                                 char *out, size_t outlen) {
    size_t oi = 0;
    const char *p = tmpl;

    while (*p && oi < outlen - 1) {
        if (*p == '$') {
            const char *start = p + 1;
            int braced = 0;
            if (*start == '{') { braced = 1; start++; }

            const char *namestart = start;
            const char *q = start;
            if (braced) {
                while (*q && *q != '}') q++;
            } else {
                while (*q && (isalnum((unsigned char)*q) || *q == '_')) q++;
            }
            size_t namelen = (size_t)(q - namestart);

            if (namelen == 0) {
                /* not a valid identifier, copy '$' literally */
                out[oi++] = *p++;
                continue;
            }

            int matched = 0;
            for (int i = 0; i < nvars; i++) {
                if (strlen(vars[i].name) == namelen &&
                    strncmp(vars[i].name, namestart, namelen) == 0) {
                    size_t vlen = strlen(vars[i].value);
                    size_t copy = vlen;
                    if (oi + copy > outlen - 1) copy = outlen - 1 - oi;
                    memcpy(out + oi, vars[i].value, copy);
                    oi += copy;
                    matched = 1;
                    break;
                }
            }

            if (matched) {
                p = q;
                if (braced && *p == '}') p++;
            } else {
                /* unknown var name -- copy literally, like Template would raise
                 * KeyError in Python; we just leave it untouched for robustness */
                out[oi++] = *p++;
            }
        } else {
            out[oi++] = *p++;
        }
    }
    out[oi] = '\0';
}

/* ------------------------------------------------------------------ */
/* Mask name mapping -- mirrors pyinotify's maskname (human readable)  */
/* ------------------------------------------------------------------ */

static const char *maskname(uint32_t mask) {
    if (mask & IN_ACCESS)        return "IN_ACCESS";
    if (mask & IN_ATTRIB)        return "IN_ATTRIB";
    if (mask & IN_CLOSE_WRITE)   return "IN_CLOSE_WRITE";
    if (mask & IN_CLOSE_NOWRITE) return "IN_CLOSE_NOWRITE";
    if (mask & IN_CREATE)        return "IN_CREATE";
    if (mask & IN_DELETE)        return "IN_DELETE";
    if (mask & IN_DELETE_SELF)   return "IN_DELETE_SELF";
    if (mask & IN_MODIFY)        return "IN_MODIFY";
    if (mask & IN_MOVE_SELF)     return "IN_MOVE_SELF";
    if (mask & IN_MOVED_FROM)    return "IN_MOVED_FROM";
    if (mask & IN_MOVED_TO)      return "IN_MOVED_TO";
    if (mask & IN_OPEN)          return "IN_OPEN";
    if (mask & IN_ISDIR)         return "IN_ISDIR";
    if (mask & IN_IGNORED)       return "IN_IGNORED";
    if (mask & IN_Q_OVERFLOW)    return "IN_Q_OVERFLOW";
    if (mask & IN_UNMOUNT)       return "IN_UNMOUNT";
    return "IN_UNKNOWN";
}

static const char *event_label(uint32_t mask) {
    if (mask & IN_ACCESS)        return "Access";
    if (mask & IN_ATTRIB)        return "Attrib";
    if (mask & IN_CLOSE_WRITE)   return "Close write";
    if (mask & IN_CLOSE_NOWRITE) return "Close nowrite";
    if (mask & IN_CREATE)        return "Creating";
    if (mask & IN_DELETE)        return "Deleteing"; /* keep original's typo for fidelity */
    if (mask & IN_MODIFY)        return "Modify";
    if (mask & IN_MOVE_SELF)     return "Move self";
    if (mask & IN_MOVED_FROM)    return "Moved from";
    if (mask & IN_MOVED_TO)      return "Moved to";
    if (mask & IN_OPEN)          return "Opened";
    return "Event";
}

/* ------------------------------------------------------------------ */
/* Mask parsing -- mirrors WatcherDaemon._parseMask()                  */
/* ------------------------------------------------------------------ */

static uint32_t parse_mask(const char *events_csv) {
    uint32_t ret = 0;
    char buf[MAX_VAL_LEN];
    snprintf(buf, sizeof(buf), "%s", events_csv);

    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok) {
        char *m = strip(tok);
        if (strcmp(m, "access") == 0) ret |= IN_ACCESS;
        else if (strcmp(m, "attribute_change") == 0) ret |= IN_ATTRIB;
        else if (strcmp(m, "write_close") == 0) ret |= IN_CLOSE_WRITE;
        else if (strcmp(m, "nowrite_close") == 0) ret |= IN_CLOSE_NOWRITE;
        else if (strcmp(m, "create") == 0) ret |= IN_CREATE;
        else if (strcmp(m, "delete") == 0) ret |= IN_DELETE;
        else if (strcmp(m, "self_delete") == 0) ret |= IN_DELETE_SELF;
        else if (strcmp(m, "modify") == 0) ret |= IN_MODIFY;
        else if (strcmp(m, "self_move") == 0) ret |= IN_MOVE_SELF;
        else if (strcmp(m, "move_from") == 0) ret |= IN_MOVED_FROM;
        else if (strcmp(m, "move_to") == 0) ret |= IN_MOVED_TO;
        else if (strcmp(m, "open") == 0) ret |= IN_OPEN;
        else if (strcmp(m, "all") == 0) {
            ret |= IN_ACCESS | IN_ATTRIB | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE |
                   IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY |
                   IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO | IN_OPEN;
        } else if (strcmp(m, "move") == 0) {
            ret |= IN_MOVED_FROM | IN_MOVED_TO;
        } else if (strcmp(m, "close") == 0) {
            ret |= IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* Exclusion filter -- mirrors pyinotify.ExcludeFilter: a list of      */
/* regexes; if any matches the full path, the path is excluded.        */
/* ------------------------------------------------------------------ */

static void compile_excludes(Job *job, const char *excluded_csv) {
    job->excl_count = 0;
    if (!excluded_csv || strip((char *)excluded_csv)[0] == '\0') return;

    char buf[MAX_VAL_LEN];
    snprintf(buf, sizeof(buf), "%s", excluded_csv);

    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok && job->excl_count < MAX_EXCLUDES) {
        char *pat = strip(tok);
        if (*pat) {
            if (regcomp(&job->excl_regex[job->excl_count], pat, REG_EXTENDED | REG_NOSUB) == 0) {
                job->excl_count++;
            } else {
                fprintf(stderr, "Warning: invalid exclude regex '%s', ignoring\n", pat);
            }
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
}

static int is_excluded(Job *job, const char *path) {
    for (int i = 0; i < job->excl_count; i++) {
        if (regexec(&job->excl_regex[i], path, 0, NULL, 0) == 0)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Recursive directory watching                                        */
/* ------------------------------------------------------------------ */

static void add_watch_recursive(Job *job, const char *path) {
    if (is_excluded(job, path)) return;
    if (job->wd_count >= MAX_WATCHES_PER) {
        log_msg("Warning: max watches (%d) reached for job [%s], not watching %s",
                MAX_WATCHES_PER, job->section, path);
        return;
    }

    int wd = inotify_add_watch(inotify_fd, path, job->mask);
    if (wd < 0) {
        log_msg("Warning: failed to watch '%s': %s", path, strerror(errno));
        return;
    }

    job->wds[job->wd_count] = wd;
    snprintf(job->wd_paths[job->wd_count], PATH_MAX, "%s", path);
    job->wd_count++;

    if (!job->recursive) return;

    DIR *d = opendir(path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char child[PATH_MAX];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);

        struct stat st;
        if (lstat(child, &st) != 0) continue;
        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            add_watch_recursive(job, child);
        }
    }
    closedir(d);
}

static const char *wd_to_path(Job *job, int wd) {
    for (int i = 0; i < job->wd_count; i++) {
        if (job->wds[i] == wd) return job->wd_paths[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Run the command for a fired event, mirrors EventHandler.runCommand  */
/* ------------------------------------------------------------------ */

static void run_command(Job *job, const char *watched_dir, const char *full_path,
                         uint32_t mask, uint32_t cookie) {
    char q_watched[PATH_MAX + 8];
    char q_filename[PATH_MAX + NAME_MAX + 16];
    char q_tflags[128];
    char q_nflags[32];
    char q_cookie[32];
    char raw_nflags[32];
    char raw_cookie[32];

    shellquote(watched_dir, q_watched, sizeof(q_watched));
    shellquote(full_path, q_filename, sizeof(q_filename));
    shellquote(maskname(mask), q_tflags, sizeof(q_tflags));

    snprintf(raw_nflags, sizeof(raw_nflags), "%u", mask);
    shellquote(raw_nflags, q_nflags, sizeof(q_nflags));

    snprintf(raw_cookie, sizeof(raw_cookie), "%u", cookie);
    shellquote(raw_cookie, q_cookie, sizeof(q_cookie));

    TemplateVar vars[] = {
        {"watched",  q_watched},
        {"filename", q_filename},
        {"tflags",   q_tflags},
        {"nflags",   q_nflags},
        {"cookie",   q_cookie},
    };

    char command[MAX_VAL_LEN * 2];
    template_substitute(job->command, vars, 5, command, sizeof(command));

    log_msg("%s: %s", event_label(mask), full_path);

    int rc = system(command);
    if (rc == -1) {
        log_msg("Failed to run command '%s': %s", command, strerror(errno));
    }
}

/* ------------------------------------------------------------------ */
/* Signal handling for clean shutdown                                  */
/* ------------------------------------------------------------------ */

static void handle_term(int signo) {
    (void)signo;
    g_terminate = 1;
}

/* ------------------------------------------------------------------ */
/* Daemonizing -- mirrors the Daemon class's double-fork + pidfile      */
/* handling from the Python version.                                   */
/* ------------------------------------------------------------------ */

static void write_pidfile(const char *pidfile) {
    FILE *f = fopen(pidfile, "w");
    if (!f) {
        fprintf(stderr, "Could not write pidfile %s: %s\n", pidfile, strerror(errno));
        exit(1);
    }
    fprintf(f, "%d\n", getpid());
    fclose(f);
}

static int read_pidfile(const char *pidfile) {
    FILE *f = fopen(pidfile, "r");
    if (!f) return -1;
    int pid = -1;
    if (fscanf(f, "%d", &pid) != 1) pid = -1;
    fclose(f);
    return pid;
}

static void daemonize(const char *pidfile, const char *logfile) {
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork #1 failed: %s\n", strerror(errno));
        exit(1);
    }
    if (pid > 0) {
        /* exit first parent */
        exit(0);
    }

    /* decouple from parent environment */
    if (chdir("/") != 0) { /* best effort */ }
    setsid();
    umask(0);

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork #2 failed: %s\n", strerror(errno));
        exit(1);
    }
    if (pid > 0) {
        exit(0);
    }

    /* redirect standard file descriptors */
    fflush(stdout);
    fflush(stderr);

    int devnull = open("/dev/null", O_RDONLY);
    int logout = open(logfile, O_CREAT | O_APPEND | O_WRONLY, 0644);
    int logerr = open(logfile, O_CREAT | O_APPEND | O_WRONLY, 0644);

    if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
    if (logout   >= 0) { dup2(logout, STDOUT_FILENO); close(logout); }
    if (logerr   >= 0) { dup2(logerr, STDERR_FILENO); close(logerr); }

    write_pidfile(pidfile);

    g_logfp = fopen(logfile, "a");
}

static void daemon_start(const char *pidfile, const char *logfile) {
    int pid = read_pidfile(pidfile);
    if (pid > 0 && kill(pid, 0) == 0) {
        fprintf(stderr, "pidfile %s already exists. Daemon already running?\n", pidfile);
        exit(1);
    }
    daemonize(pidfile, logfile);
}

static void daemon_stop(const char *pidfile) {
    int pid = read_pidfile(pidfile);
    if (pid <= 0) {
        fprintf(stderr, "pidfile %s does not exist. Daemon not running?\n", pidfile);
        return;
    }

    while (kill(pid, SIGTERM) == 0) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 }; /* 0.1s */
        nanosleep(&ts, NULL);
    }

    if (errno == ESRCH) {
        if (access(pidfile, F_OK) == 0) {
            unlink(pidfile);
        }
    } else {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(1);
    }
}

static void daemon_status(const char *pidfile) {
    int pid = read_pidfile(pidfile);
    if (pid > 0 && kill(pid, 0) == 0) {
        printf("service running\n");
        exit(0);
    }
    printf("service not running\n");
    exit(3);
}

/* ------------------------------------------------------------------ */
/* Job setup from config, mirrors WatcherDaemon.run()'s job-loading    */
/* loop (minus the DEFAULT pseudo-section, which holds daemon config). */
/* ------------------------------------------------------------------ */

static void setup_jobs(Config *cfg) {
    job_count = 0;
    for (int i = 0; i < cfg->section_count; i++) {
        Section *sec = &cfg->sections[i];
        if (strcmp(sec->name, "DEFAULT") == 0) continue;

        if (job_count >= MAX_SECTIONS) {
            log_msg("Too many watch sections, ignoring [%s]", sec->name);
            continue;
        }

        Job *job = &jobs[job_count];
        memset(job, 0, sizeof(*job));
        snprintf(job->section, sizeof(job->section), "%s", sec->name);

        const char *events   = cfg_get(cfg, sec, "events", 1, NULL);
        const char *watch    = cfg_get(cfg, sec, "watch", 1, NULL);
        const char *command  = cfg_get(cfg, sec, "command", 1, NULL);
        const char *excluded = cfg_get(cfg, sec, "excluded", 0, "");

        job->recursive = cfg_get_bool(cfg, sec, "recursive", 1, 0);
        job->autoadd   = cfg_get_bool(cfg, sec, "autoadd", 1, 0);
        job->mask      = parse_mask(events);

        snprintf(job->folder, sizeof(job->folder), "%s", watch);
        snprintf(job->command, sizeof(job->command), "%s", command);

        compile_excludes(job, excluded);

        log_msg("%s: %s", sec->name, watch);

        job_count++;
    }
}

static void start_watches(void) {
    inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd < 0) {
        log_msg("inotify_init1 failed: %s", strerror(errno));
        exit(1);
    }

    for (int i = 0; i < job_count; i++) {
        add_watch_recursive(&jobs[i], jobs[i].folder);
    }
}

static Job *job_for_wd(int wd) {
    for (int i = 0; i < job_count; i++) {
        for (int j = 0; j < jobs[i].wd_count; j++) {
            if (jobs[i].wds[j] == wd) return &jobs[i];
        }
    }
    return NULL;
}

/* Main event loop: read inotify events and dispatch to the matching
 * job's command, same overall effect as pyinotify's ThreadedNotifier
 * loop but implemented as a single-threaded select() loop using only
 * the standard library + raw inotify syscalls. */
static void event_loop(void) {
    char buf[INOTIFY_BUF_LEN];

    while (!g_terminate) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(inotify_fd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(inotify_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            log_msg("select() failed: %s", strerror(errno));
            break;
        }
        if (rc == 0) continue; /* timeout, loop to check g_terminate */

        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            log_msg("read() failed: %s", strerror(errno));
            break;
        }

        ssize_t offset = 0;
        while (offset < len) {
            struct inotify_event *ev = (struct inotify_event *)(buf + offset);

            Job *job = job_for_wd(ev->wd);
            if (job) {
                const char *dirpath = wd_to_path(job, ev->wd);
                const char *base = dirpath ? dirpath : job->folder;
                char full_path[PATH_MAX + NAME_MAX + 2];
                if (ev->len > 0) {
                    snprintf(full_path, sizeof(full_path), "%s/%s", base, ev->name);
                } else {
                    snprintf(full_path, sizeof(full_path), "%s", base);
                }

                if (!is_excluded(job, full_path)) {
                    /* auto_add: if a new directory was created and this job
                     * is recursive/autoadd, start watching it too */
                    if (job->autoadd && (ev->mask & IN_CREATE) && (ev->mask & IN_ISDIR)) {
                        add_watch_recursive(job, full_path);
                    }

                    if (ev->mask & job->mask) {
                        run_command(job, dirpath ? dirpath : job->folder,
                                    full_path, ev->mask, ev->cookie);
                    }
                }
            }

            offset += (ssize_t)(sizeof(struct inotify_event) + ev->len);
        }
    }
}

static void run_daemon(void) {
    log_msg("Daemon started");
    start_watches();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    event_loop();

    log_msg("Daemon stopping");
    if (inotify_fd >= 0) close(inotify_fd);
}

/* ------------------------------------------------------------------ */
/* Argument parsing -- mirrors argparse usage in the Python version    */
/* ------------------------------------------------------------------ */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "usage: %s [-c CONFIG] {start,stop,restart,status,debug}\n\n"
        "A daemon to monitor changes within specified directories and run\n"
        "commands on these changes.\n\n"
        "positional arguments:\n"
        "  {start,stop,restart,status,debug}\n"
        "                        What to do. Use debug to start in the foreground\n\n"
        "options:\n"
        "  -c CONFIG, --config CONFIG\n"
        "                        Path to the config file (default: /etc/watcher.ini)\n",
        prog);
}

int main(int argc, char **argv) {
    const char *config_path = NULL;
    const char *command = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: option '%s' requires a value\n", argv[0], argv[i]);
                return 2;
            }
            config_path = argv[++i];
        } else if (strncmp(argv[i], "--config=", 9) == 0) {
            config_path = argv[i] + 9;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (!command) {
            command = argv[i];
        } else {
            fprintf(stderr, "%s: unrecognized argument '%s'\n", argv[0], argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (!command) {
        print_usage(argv[0]);
        return 2;
    }

    if (strcmp(command, "start") != 0 && strcmp(command, "stop") != 0 &&
        strcmp(command, "restart") != 0 && strcmp(command, "status") != 0 &&
        strcmp(command, "debug") != 0) {
        fprintf(stderr, "%s: invalid command '%s' (choose from start, stop, restart, status, debug)\n",
                argv[0], command);
        return 2;
    }

    /* Parse the config file */
    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int confok = 0;
    if (config_path) {
        confok = parse_ini_file(config_path, &cfg);
    } else {
        char home_conf[PATH_MAX];
        const char *home = getenv("HOME");
        if (home) {
            snprintf(home_conf, sizeof(home_conf), "%s/.watcher.ini", home);
        } else {
            home_conf[0] = '\0';
        }

        if (parse_ini_file("/etc/watcher.ini", &cfg)) confok = 1;
        if (home_conf[0] && parse_ini_file(home_conf, &cfg)) confok = 1;
    }

    if (!confok) {
        fprintf(stderr, "Failed to read config file. Try -c parameter\n");
        return 4;
    }

    Section *defsec = find_or_add_section(&cfg, "DEFAULT");
    snprintf(g_logfile, sizeof(g_logfile), "%s", cfg_get(&cfg, defsec, "logfile", 1, NULL));
    snprintf(g_pidfile, sizeof(g_pidfile), "%s", cfg_get(&cfg, defsec, "pidfile", 1, NULL));

    setup_jobs(&cfg);

    if (strcmp(command, "start") == 0) {
        daemon_start(g_pidfile, g_logfile);
        run_daemon();
    } else if (strcmp(command, "stop") == 0) {
        daemon_stop(g_pidfile);
    } else if (strcmp(command, "restart") == 0) {
        daemon_stop(g_pidfile);
        daemon_start(g_pidfile, g_logfile);
        run_daemon();
    } else if (strcmp(command, "status") == 0) {
        daemon_status(g_pidfile);
    } else if (strcmp(command, "debug") == 0) {
        run_daemon();
    }

    return 0;
}
