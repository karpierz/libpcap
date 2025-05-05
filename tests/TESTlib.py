# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

# TESTrun helper functions (common to all projects).

import sys
import os
import tempfile
import re
#use Config;
#use File::Temp qw(tempdir);
# TESTst.pm or TESTmt.pm
try:
    import threading
except ImportError:
    from TESTst import get_next_result, my_tmp_id, start_tests
else:
    from TESTmt import get_next_result, my_tmp_id, start_tests

# The characters are inspired by PHPUnit format,
# but are not exactly the same.
CHAR_SKIPPED   = "S"
CHAR_PASSED    = "."
CHAR_FAILED    = "F"
CHAR_TIMED_OUT = "T"

osnames = {
    "aix":       "AIX",
    "darwin":    "macOS",
    "dragonfly": "DragonFly BSD",
    "freebsd":   "FreeBSD",
    "gnu":       "Hurd",
    "haiku":     "Haiku",
    "hpux":      "HP-UX",
    "linux":     "Linux",
    "msys":      "Windows",
    "netbsd":    "NetBSD",
    "openbsd":   "OpenBSD",
    "solaris":   "illumos/Solaris",
}

results_to_print = 0
results_printed  = 0
max_result_digits    = 0
max_results_per_line = 0
flush_after_newline  = False
config = {}
tmpdir = None


def die(msg=None):
    import os.abort
    if msg is not None: print(msg)
    abort()


def init_tmpdir(prefix):
    global tmpdir
    tmpdir = tempfile.mkdtemp(prefix=f"{prefix}_XXXXXXXX")
    #tmpdir = tempdir (
    #    f"{prefix}_XXXXXXXX",
    #    "TMPDIR":  1,
    #    "CLEANUP": 1,
    #)


def mytmpfile(filename):
    return "%s/%s-%s" % (tmpdir, my_tmp_id(), filename)


def get_njobs():
    njobs: int
    if "TESTRUN_JOBS" not in os.environ:
        njobs = 1
    elif re.search(r"^\d+\z", os.environ["TESTRUN_JOBS"]):
        njobs = int(os.environ["TESTRUN_JOBS"])
    else:
        njobs = 0
    if not njobs: # ???
        die(f"ERROR: '{os.environ['TESTRUN_JOBS']}' is "
            "not a valid value for TESTRUN_JOBS")
    return njobs


def get_diff_flags():
    return os.environ.get("DIFF_FLAGS", "-c" if os.name == "hpux" else "-u")


def read_config_h(config_h):
    # Parse config.h into a hash for later use.
    global config
    config = {}
    try:
        fh = open(config_h, "rt")
    except:
        die(f"failed opening '{config_h}'")
    for line in fh:
        match = re.search(r'''/^[[:blank:]]*\#define
                          [[:blank:]]+([0-9_A-Z]+)
                          [[:blank:]]+([0-9]+|".*")
                          [\r\n]*$''', line, '/xo')
        if match:
            config[match.group(1)] = match.group(2)
    try:
        fh.close()
    except:
        die(f"failed closing '{config_h}'")
    return config


def file_put_contents(filename, contents):
    # This is a simpler version of the PHP function.
    try:
        fh = open(filename, "wt")
    except:
        die(f"failed opening '{filename}'")
    fh.write(contents)
    try:
        fh.close()
    except:
        die(f"failed closing '{filename}'")


def file_get_contents(filename):
    # Idem.
    try:
        fh = open(filename, "rt")
    except:
        die(f"failed opening '{filename}'")
    ret = ""
    for line in fh:
        ret += line
    try:
        fh.close()
    except:
        die(f"failed closing '{filename}'")
    return ret


def string_in_file(string, filename) -> bool:
    ret = False
    try:
        fh = open(filename, "rt")
    except:
        die(f"failed opening '{filename}'")
    for line in fh:
        if string in line:
            ret = True
            break
    try:
        fh.close()
    except:
        die(f"failed closing '{filename}'")
    return ret


def skip_os(name):
    bettername = osnames.get(name, name)
    return f"is {bettername}" if os.name == name else ""


def skip_os_not(name):
    bettername = osnames.get(name, name)
    return f"is not {bettername}" if os.name != name else ""


def skip_config_def1(symbol):
    return f"{symbol}==1" if symbol in config and config[symbol] == "1" else ""


def skip_config_undef(symbol):
    return f"{symbol}!=1" if symbol not in config or config[symbol] != "1" else ""


def skip_config_have_decl(name, value):
    name = "HAVE_DECL_" + name
    # "Unlike the other ‘AC_CHECK_*S’ macros, when a symbol is not declared,
    # HAVE_DECL_symbol is defined to ‘0’ instead of leaving HAVE_DECL_symbol
    # undeclared." -- GNU Autoconf manual.
    #
    # (This requires the CMake leg to do the same for the same symbol.)
    if name not in config: die(f"no {name} in config.h")
    return f"{name}=={value}" if int(config[name]) == value else ""


def result_skipped(skip):
    return {
        "char": CHAR_SKIPPED,
        "skip": skip,
    }


def result_passed(T):
    return {
        "char": CHAR_PASSED,
        "T": T,
    }


def result_failed(reason, details):
    return {
        "char": CHAR_FAILED,
        "failure": {
            "reason": reason,
            "details": details,
        },
    }


def result_timed_out(reason):
    return {
        "char": CHAR_TIMED_OUT,
        "failure": {"reason": reason}
    }


def run_skip_test(test):
    return result_skipped(test["skip"])


def init_results_processing(shift):
    global results_printed, results_to_print
    global max_result_digits, max_results_per_line
    # <------------------------- maxcols -------------------------->
    # ............................................ 0000 / 0000 (000%)
    #                          max_result_digits >----< >----<
    # <--------- max_results_per_line ---------->
    maxcols = 80
    results_to_print = shift;
    if Config["useithreads"]:
        # When using threads, STDOUT becomes line-buffered on TTYs, which is
        # not good for interactive progress monitoring.
        if sys.stdout.isatty():
            STDOUT.autoflush(1)
        flush_after_newline = not sys.stdout.isatty()
    results_printed = 0
    max_result_digits = 1 + int(log(results_to_print) / log(10))
    max_results_per_line = maxcols - 11 - 2 * max_result_digits


def print_result_char(result_char):
    # Produce a results map in PHPUnit output format.
    global results_printed
    print(result_char, end="")
    results_printed += 1
    if results_printed > results_to_print:
        die("Internal error: unexpected results after 100%!")
    results_dangling = results_printed % max_results_per_line
    if results_dangling:
        if results_printed < results_to_print:
            return
        # Complete the dangling line to keep the progress column aligned.
        print(" " * (max_results_per_line - results_dangling), end="")
    print(" %*u / %*u (%3u%%)" % (
          max_result_digits, results_printed,
          max_result_digits, results_to_print,
          100 * results_printed / results_to_print))
    # When using threads, STDOUT becomes block-buffered on pipes, which is
    # not good for CI progress monitoring.
    if flush_after_newline:
        sys.stdout.flush()


def print_result(label, msg):
    print("    %-40s: %s" % (label, msg))


def test_and_report(tests): # @tests

    seen_labels = {}
    for test in tests:
        label = test["label"]
        if label in seen_labels:
            die(f"ERROR: Duplicate test label '{label}'")
        seen_labels[label] = 1
    del seen_labels

    start_tests(tests)
    init_results_processing(len(tests))

    ret = 0

    # key: test label, value: reason for skipping
    skipped = {}
    # key: test label, value: hash of
    # * reason (mandatory, string)
    # * details (optional, [multi-line] string)
    failed = {}
    passed = {}  # May stay empty even if passedcount > 0.
    passedcount = 0

    print("INFO: %s = skipped, %s = passed, %s = failed, %s = timed out" %
          CHAR_SKIPPED, CHAR_PASSED, CHAR_FAILED, CHAR_TIMED_OUT)

    # Ordering of the results is the same as ordering of the tests.  Print the
    # results map immediately and buffer any skipped/failed test details for the
    # post-map diagnostics.
    while (result := get_next_result()) is not None:
        print_result_char(result["char"])
        if "skip" in result:
            skipped[result["label"]] = result["skip"]
        elif "failure" in result:
            failed[result["label"]] = result["failure"]
        else:
            passedcount += 1
            if "T" in result:
                passed[result["label"]] = result["T"]

    print()
    if passed:
        print("Passed tests:")
        for label in sorted(passed.keys()):
            print_result(label, "T=%.06fs" % passed[label])
        print()
    if skipped:
        print("Skipped tests:")
        for label in sorted(skipped.keys()):
            if skipped[label] != "":
                print_result(label, skipped[label])
        print()
    if failed:
        ret = 1;
        print("Failed tests:")
        for label in sorted(failed.keys()):
            print_result(label, failed[label]["reason"])
            if "details" in failed[label]:
                print(failed[label]["details"], end="")
        print()

    # scalar (%hash) returns incorrect value on Perl 5.8.4.
    skippedcount = len(skipped)
    failedcount  = len(failed)
    print("------------------------------------------------")
    print("%4u tests skipped" % skippedcount)
    print("%4u tests failed"  % failedcount)
    if not passed:
        # There isn't any test duration statistics.
        print("%4u tests passed" % passedcount)
    elif passedcount != len(passed):
        die("Internal error: statistics bug (%u != %u)" % (
            passedcount, len(passed)))
    else:
        print("%4u tests passed: T min/avg/max = %.06f/%.06f/%.06fs" % (
              len(passed),
              min(passed.values()),
              sum(passed.values()) / len(passed),
              max(passed.values())))

    if skippedcount + failedcount + passedcount != results_to_print:
        print("Internal error: statistics bug (%u + %u + %u != %u)" % (
              skippedcount, failedcount, passedcount, results_to_print),
              file=sys.stderr)
        ret = 2

    return ret
