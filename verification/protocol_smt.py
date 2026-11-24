"""SMT inductive checks for the HDT control protocol, not a crypto primitive proof.
Run with `python -m verification.protocol_smt`; z3-solver CLI or libz3 required.
"""
import ctypes
import ctypes.util
import shutil
import subprocess

FIELDS = [('p', 'Int'), ('n', 'Int'), ('t', 'Int'), ('short', 'Bool'),
          ('prefix', 'Bool'), ('budgeted', 'Bool'), ('header', 'Bool'),
          ('final', 'Bool'), ('out', 'Bool')]
INPUTS = [('parse_ok', 'Bool'), ('budget_ok', 'Bool'), ('derive_ok', 'Bool'),
          ('commit_ok', 'Bool'), ('unwrap_ok', 'Bool'), ('mac_ok', 'Bool'),
          ('kind', 'Int'), ('idx', 'Int'), ('length', 'Int'), ('tag', 'Bool'),
          ('genuine', 'Bool'), ('ftag', 'Bool'), ('fn', 'Int'), ('ft', 'Int'),
          ('eof', 'Bool'), ('io_ok', 'Bool'), ('link_ok', 'Bool')]


def AND(*args): return '(and ' + ' '.join(args) + ')'
def OR(*args): return '(or ' + ' '.join(args) + ')'
def NOT(x): return f'(not {x})'
def EQ(a, b): return f'(= {a} {b})'
def IMPLIES(a, b): return f'(=> {a} {b})'


def state(**updates):
    return AND(*(EQ(k+'2', str(updates.get(k, k))) for k, _ in FIELDS))


def invariant(suffix=''):
    p, n, t, short, prefix, budgeted, header, final, out = (k+suffix for k, _ in FIELDS)
    active = f'(<= 0 {p} 7)'
    return AND(f'(<= 0 {p} 8)', EQ(out, EQ(p, 7)),
        IMPLIES(active, AND(f'(<= 0 {n} N)', EQ(t, f'(ite (< {n} N) (* {n} CHUNK) L)'),
                            prefix, EQ(short, AND(f'(> {n} 0)', EQ(n, 'N'), '(< last CHUNK)')))),
        IMPLIES(f'(<= 0 {p} 4)', EQ(n, 0)),
        IMPLIES(active, EQ(budgeted, f'(> {p} 0)')),
        IMPLIES(active, EQ(header, f'(>= {p} 5)')),
        IMPLIES(active, EQ(final, f'(>= {p} 6)')),
        IMPLIES(f'(<= 6 {p} 7)', AND(EQ(n, 'N'), EQ(t, 'L'))))


def query(label, formula, expected='unsat'):
    return f'(echo "{label}|{expected}")\n(push)\n(assert {formula})\n(check-sat)\n(pop)\n'


def build():
    src = ['(set-logic ALL)', '(declare-const N Int)', '(declare-const L Int)',
           '(declare-const last Int)', '(define-fun CHUNK () Int 1048576)',
           '(define-fun MAX () Int 4294967295)',
           '(assert (and (<= 0 N MAX) (ite (= N 0) (and (= L 0) (= last 0)) (and (<= 1 last CHUNK) (= L (+ (* (- N 1) CHUNK) last))))))']
    for name, typ in FIELDS:
        src += [f'(declare-const {name} {typ})', f'(declare-const {name}2 {typ})']
    src += [f'(declare-const {name} {typ})' for name, typ in INPUTS]
    # Authenticated tokens are genuine in the fixed honest-header/no-forgery game.
    src += ['(assert (=> tag (and genuine (<= 0 idx) (< idx N) (= length (ite (= idx (- N 1)) last CHUNK)))))',
            '(assert (=> ftag (and (= fn N) (= ft L))))']
    init = AND(EQ('p', 0), EQ('n', 0), EQ('t', 0), NOT('short'), 'prefix',
               NOT('budgeted'), NOT('header'), NOT('final'), NOT('out'))
    guards = [AND('parse_ok', 'budget_ok'), 'derive_ok', 'commit_ok', 'unwrap_ok', 'mac_ok']
    transitions = []
    for stage, guard in enumerate(guards):
        changes = {'p': stage+1}
        if stage == 0: changes['budgeted'] = 'true'
        if stage == 4: changes['header'] = 'true'
        transitions += [AND(EQ('p', stage), guard, state(**changes)),
                        AND(EQ('p', stage), NOT(guard), state(p=8))]
    data = AND(EQ('kind', 1), NOT('short'), EQ('idx', 'n'), '(<= 1 length CHUNK)', '(< n MAX)', 'tag', 'io_ok')
    end = AND(EQ('kind', 2), 'ftag', EQ('fn', 'n'), EQ('ft', 't'), 'eof', 'io_ok')
    transitions += [AND(EQ('p', 5), data, state(n='(+ n 1)', t='(+ t length)', short='(< length CHUNK)', prefix=AND('prefix', 'genuine'))),
                    AND(EQ('p', 5), end, state(p=6, final='true')),
                    AND(EQ('p', 5), NOT(OR(data, end)), state(p=8)),
                    AND(EQ('p', 6), 'link_ok', state(p=7, out='true')),
                    AND(EQ('p', 6), NOT('link_ok'), state(p=8)),
                    AND('(<= 0 p 6)', state(p=8)),  # crash before publication; fail closed
                    AND(OR(EQ('p', 7), EQ('p', 8)), state())]
    inv, inv2, trans = invariant(), invariant('2'), OR(*transitions)
    src += [f'(define-fun inv () Bool {inv})', f'(define-fun inv2 () Bool {inv2})', f'(define-fun step () Bool {trans})']
    src += [query('initial-invariant', AND(init, NOT('inv'))),
            query('inductive-step-all-transitions', AND('inv', 'step', NOT('inv2'))),
            query('published-implies-complete', AND('inv', 'out', NOT(AND('budgeted', 'header', 'final', 'prefix', EQ('n', 'N'), EQ('t', 'L'))))),
            query('no-premature-link', AND('inv', 'step', NOT('out'), 'out2', NOT(EQ('p', 6)))),
            query('reject-budget-before-kdf', AND('inv', 'step', EQ('p', 0), NOT('budget_ok'), EQ('p2', 1))),
            query('reject-wrong-commit', AND('inv', 'step', EQ('p', 2), NOT('commit_ok'), EQ('p2', 3))),
            query('reject-bad-header-mac', AND('inv', 'step', EQ('p', 4), NOT('mac_ok'), EQ('p2', 5))),
            query('reject-trailing-bytes', AND('inv', 'step', EQ('p', 5), EQ('kind', 2), NOT('eof'), EQ('p2', 6))),
            query('reject-short-nonfinal', AND('inv', 'step', EQ('p', 5), 'short', EQ('kind', 1), EQ('p2', 5))),
            query('failed-state-absorbing', AND('inv', 'step', EQ('p', 8), NOT(EQ('p2', 8)))),
            query('one-valid-data-transition-exists', AND('inv', 'step', EQ('p', 5), EQ('n', 0), '(> N 0)', EQ('p2', 5), EQ('n2', 1)), 'sat'),
            query('one-valid-publish-transition-exists', AND('inv', 'step', EQ('p', 6), EQ('p2', 7)), 'sat'),
            query('negative-control-premature-publish', AND('inv', EQ('p', 5), state(p=7, out='true'), NOT('inv2')), 'sat')]
    # Algebraic reduction: the hash input constructor is injective by canonical encoding.
    src += ['(declare-sort Bytes 0)', '(declare-datatypes () ((CommitInput (enc (h Bytes) (kw Bytes) (kc Bytes)))))',
            '(declare-fun digest (CommitInput) Bytes)', '(declare-const H Bytes)', '(declare-const K1 Bytes)', '(declare-const K2 Bytes)', '(declare-const C1 Bytes)', '(declare-const C2 Bytes)',
            '(define-fun X () CommitInput (enc H K1 C1))', '(define-fun Y () CommitInput (enc H K2 C2))',
            '(declare-fun dec (Bytes Bytes Bytes) Bytes)', '(declare-const W Bytes)']
    same = EQ('(digest X)', '(digest Y)')
    no_collision = IMPLIES(same, EQ('X','Y'))
    src += [query('chosen-key-ambiguity-implies-hash-collision', AND(same, NOT(EQ('K1','K2')), EQ('X','Y'))),
            query('binding-under-no-collision', AND(no_collision, same, NOT(EQ('K1','K2')))),
            query('equal-committed-key-deterministic-unwrap', AND(no_collision, same, NOT(EQ('(dec K1 H W)', '(dec K2 H W)')))),
            query('collision-assumption-is-necessary', AND(same, NOT(EQ('K1','K2'))), 'sat')]
    return '\n'.join(src)


def solve(source):
    exe = shutil.which('z3')
    if exe:
        return subprocess.run([exe, '-in'], input=source, text=True, check=True, capture_output=True, timeout=30).stdout
    lib = ctypes.util.find_library('z3')
    if not lib:
        raise RuntimeError('Install z3-solver or libz3')
    z = ctypes.CDLL(lib)
    z.Z3_mk_config.restype = ctypes.c_void_p
    z.Z3_mk_context.argtypes = [ctypes.c_void_p]; z.Z3_mk_context.restype = ctypes.c_void_p
    z.Z3_del_config.argtypes = [ctypes.c_void_p]
    z.Z3_del_context.argtypes = [ctypes.c_void_p]
    z.Z3_eval_smtlib2_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p]; z.Z3_eval_smtlib2_string.restype = ctypes.c_char_p
    cfg = z.Z3_mk_config(); ctx = z.Z3_mk_context(cfg); z.Z3_del_config(cfg)
    try:
        return z.Z3_eval_smtlib2_string(ctx, source.encode()).decode()
    finally:
        z.Z3_del_context(ctx)


def run():
    lines = [x.strip().strip('"') for x in solve(build()).splitlines() if x.strip()]
    assert len(lines) == 34, lines
    for label, actual in zip(lines[::2], lines[1::2]):
        name, expected = label.split('|')
        assert actual == expected, (name, actual, expected)
        print(f'{name}: {actual} (expected)', flush=True)
    print('PASS: 13 UNSAT obligations, 4 SAT positive/negative controls')


if __name__ == '__main__':
    run()
