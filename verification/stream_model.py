"""Finite state abstraction: authenticated tokens cannot be forged.
No claim about primitive security, unbounded traces, or implementation refinement.
"""
from itertools import product


def accept(seq):
    index = total = 0
    short = False
    for pos, (kind, stream, i, n) in enumerate(seq):
        if stream != 0:
            return False
        if kind == "F":
            return (i, n) == (index, total) and pos == len(seq) - 1
        if kind != "D" or short or i != index or n not in (1, 2) or index >= 3:
            return False
        index += 1
        total += n
        short = n < 2
    return False


def check():
    cases = 0
    for lengths in [(), (1,), (2,), (2, 1), (2, 2), (2, 2, 1), (2, 2, 2)]:
        genuine = tuple(("D", 0, i, n) for i, n in enumerate(lengths)) + (("F", 0, len(lengths), sum(lengths)),)
        alphabet = genuine + tuple((k, 1, i, n) for k, _, i, n in genuine)
        for size in range(len(genuine) + 2):
            for seq in product(alphabet, repeat=size):
                cases += 1
                assert accept(seq) == (seq == genuine), (genuine, seq)
    return cases


if __name__ == "__main__":
    print("checked", check(), "traces; no non-original accepted")
