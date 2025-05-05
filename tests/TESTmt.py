# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

# TESTrun helper functions (multithreaded implementation).

import threading
import queue

from TESTlib import get_njobs, die

tests = []
njobs = 0
tmpid = None

tester_threads = []
result_queues  = []
next_to_dequeue: int


def my_tmp_id():
    return tmpid


def start_tests(*args):
    global tests, njobs
    global tester_threads
    global result_queues
    global next_to_dequeue
    njobs = get_njobs()
    print(f"INFO: This Python supports threads, using {njobs} tester thread(s).")
    tests = list(args)
    tester_threads = []
    result_queues  = []
    for jobid in range(njobs):
        try:
            thread = threading.Thread(target=tester_thread_func, args=(jobid,))
            thread.start()
        except Exception as exc:
            die("Couldn't run thread for jobid %d, error %s" % (jobid, exc))
        tester_threads.append(thread)
        result_queues.append(queue.Queue())
    next_to_dequeue = 0


def tester_thread_func(jobid):
    # Iterate over the list of tests, pick tests that belong to the current job,
    # run one test at a time and send the result to the job's results queue.
    global tmpid
    global result_queues
    tmpid = "job%03u" % jobid
    for i in range(jobid, len(tests), njobs):
        test = tests[i]
        result = test["func"](test)
        result["label"] = test["label"]
        result_queues[jobid].put(result)
    # Instead of detaching let the receiver join, this works around File::Temp
    # not cleaning up.
    # No Thread::Queue->end() in Perl 5.10.1, so use an undef to mark the end.
    result_queues[jobid].put(None)


def get_next_result():
    # Here ordering of the results is the same as ordering of the tests because
    # this function starts at job 0 and continues round-robin, which reverses the
    # interleaving done in the thread function above; also because every attempt
    # to dequeue blocks until it returns exactly one result.
    global tester_threads
    global result_queues
    global next_to_dequeue
    for i in range(njobs):
        jobid = next_to_dequeue
        next_to_dequeue = (next_to_dequeue + 1) % njobs
        # Skip queues that have already ended.
        try:
            result_queues[jobid]
        except IndexError:
            continue
        result = result_queues[jobid].get()
        # A test result?
        if result is not None:
            return result
        # No, an end-of-queue marker.
        result_queues[jobid].shutdown()
        result_queues[jobid] = None
        tester_threads[jobid].join()
    # No results after one complete round, therefore done.
    return None
