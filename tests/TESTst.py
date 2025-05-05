# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

# TESTrun helper functions (single-threaded implementation).

from TESTlib import get_njobs, die

tests = []


def my_tmp_id():
    return "main"


def start_tests(*args):
    global tests
    print("INFO: This Python does not support threads.")
    njobs = get_njobs()
    if njobs > 1:
        die(f"ERROR: Impossible to run {njobs} tester threads!")
    tests = list(args)


def get_next_result():
    # Here ordering of the results is obviously the same as ordering
    # of the tests.
    try:
        test = tests.pop(0)
    except IndexError:
        return None
    result = test["func"](test)
    result["label"] = test["label"]
    return result
