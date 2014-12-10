#!/usr/bin/env python

from __future__ import print_function

from bisect import bisect_left

from gmul import gmul

def delta_gen(i):
    ii = iter(i)
    prev = next(ii)
    for a in ii:
        yield(a - prev)
        prev = a

def index(a, x):
    'Locate the leftmost value exactly equal to x'
    i = bisect_left(a, x)
    if i != len(a) and a[i] == x:
        return i
    raise ValueError

def brauer_gen(fd):
    for line in fd:
        line = line.strip()
        num_line, tag = line.rsplit(" ", 1)
        if tag == "b":
            nums = tuple( int(x) for x in num_line.split(" ") )
            deltas = tuple(delta_gen(nums))
            indices = tuple( index(nums, x) - i for i, x in enumerate(delta_gen(nums)) )
            yield indices

def main():
    best = (-100, ())
    with open("ac0254.txt") as f:
        for a in brauer_gen(f):
            #print(a)
            worst_delta = min(a)
            #print("    ", worst_delta)

            if 0:
                if worst_delta >= best[1]:
                    best = (worst_delta, a)
                    print(best)
            if 1:
                if worst_delta >= -3:
                    print((worst_delta, a))

    #print("Best:", best)
            

if __name__ == "__main__":
    main()

