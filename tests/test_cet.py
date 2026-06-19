"""
Phase 0 tests for the CET-resistant JOP/COP engine.

Covers contracts:
  C0 - legacy behavior preserved when CET is off / no note
  C1 - arch CET detection: apply_cet truth table, addr_has_endbr pure/total, ibt => endbr_bytes
  C2 - gadget has_endbr tagging (bool, endbr-aware, pickle/stale-cache survival)
  C7 - legacy-path IBT enforcement (Builder._check_ibt consecutive-pair gate)

These use self-contained fixtures under tests/fixtures (built by build.sh with a
gcc that supports -fcf-protection), so they do not depend on the external
angr/binaries repo:
  - cet_probe : -fcf-protection=full  -> GNU property note advertises IBT+SHSTK
  - nocet     : -fcf-protection=none  -> no x86-feature note (endbr bytes from
                static glibc may still be present, proving detection is note-based)
"""
import os
import pickle

import pytest
import angr
import angrop  # noqa: F401  pylint: disable=unused-import
from angrop.arch import get_arch
from angrop.errors import RopException
from angrop.rop_gadget import RopGadget

FIXTURES = os.path.join(os.path.dirname(os.path.realpath(__file__)), "fixtures")
CET_BIN = os.path.join(FIXTURES, "cet_probe")
NOCET_BIN = os.path.join(FIXTURES, "nocet")

# Stable addresses in the committed cet_probe binary (see build.sh / objdump).
ENDBR_GADGET = 0x401865   # add2:  endbr64; lea rax,[rdi+rsi]; ret  (entry IS endbr)
NONENDBR_GADGET = 0x4016f9  # pop rbp; ret                          (entry is NOT endbr)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _arch(path):
    p = angr.Project(path, auto_load_libs=False)
    return get_arch(p)


# --------------------------------------------------------------------------- #
# C1 - arch / CET detection
# --------------------------------------------------------------------------- #
def test_apply_cet_force_off():
    arch = _arch(CET_BIN)
    arch.apply_cet(False)
    assert arch.ibt is False and arch.shstk is False


def test_apply_cet_force_on_x86():
    arch = _arch(CET_BIN)
    arch.apply_cet(True)
    assert arch.ibt is True and arch.shstk is True


def test_apply_cet_autodetect_full():
    # cet_probe is compiled -fcf-protection=full -> note advertises IBT + SHSTK
    arch = _arch(CET_BIN)
    ibt, shstk = arch.apply_cet(None)
    assert ibt is True and shstk is True


def test_apply_cet_autodetect_absent():
    # nocet has no x86-feature note even though static glibc leaves endbr bytes:
    # detection is note-based, so CET must read as off.
    arch = _arch(NOCET_BIN)
    ibt, shstk = arch.apply_cet(None)
    assert ibt is False and shstk is False


def test_ibt_implies_endbr_bytes():
    # invariant: ibt => endbr_bytes is not None (only x86/amd64 can set ibt)
    arch = _arch(CET_BIN)
    arch.apply_cet(True)
    assert (not arch.ibt) or arch.endbr_bytes is not None


def test_addr_has_endbr_true_false():
    arch = _arch(CET_BIN)
    arch.apply_cet(True)
    assert arch.addr_has_endbr(ENDBR_GADGET) is True
    # bytes mid-/post-endbr are not the opcode
    assert arch.addr_has_endbr(ENDBR_GADGET + 4) is False


def test_addr_has_endbr_total():
    # pure & total: never raises, always bool, even on unmapped addresses
    arch = _arch(CET_BIN)
    arch.apply_cet(True)
    for addr in (0x0, 0xdeadbeef, 0xffffffffffffffff, ENDBR_GADGET):
        res = arch.addr_has_endbr(addr)
        assert isinstance(res, bool)


def test_addr_has_endbr_none_bytes_always_false():
    # endbr_bytes is None  =>  predicate is False for all inputs
    arch = _arch(CET_BIN)
    arch.endbr_bytes = None
    for addr in (0x0, ENDBR_GADGET, 0xdeadbeef):
        assert arch.addr_has_endbr(addr) is False


# --------------------------------------------------------------------------- #
# C2 - gadget has_endbr tagging
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def cet_rop():
    p = angr.Project(CET_BIN, auto_load_libs=False)
    return p.analyses.ROP(cet=True)


def test_rop_exposes_ibt_shstk(cet_rop):
    assert cet_rop.ibt is True and cet_rop.shstk is True


def test_gadget_has_endbr_true(cet_rop):
    g = cet_rop.analyze_gadget(ENDBR_GADGET)
    assert g is not None
    assert g.has_endbr is True


def test_gadget_has_endbr_false(cet_rop):
    g = cet_rop.analyze_gadget(NONENDBR_GADGET)
    assert g is not None
    assert g.has_endbr is False


def test_has_endbr_is_bool(cet_rop):
    g = cet_rop.analyze_gadget(NONENDBR_GADGET)
    assert isinstance(g.has_endbr, bool)


def test_has_endbr_survives_pickle(cet_rop):
    g = cet_rop.analyze_gadget(ENDBR_GADGET)
    g2 = pickle.loads(pickle.dumps(g))
    assert g2.has_endbr == g.has_endbr is True


def test_setstate_stale_cache_defaults_false():
    # a gadget pickled before has_endbr existed must unpickle with has_endbr == False
    g = RopGadget(0x401865)
    state = g.__getstate__()
    state.pop("has_endbr", None)
    stale = RopGadget.__new__(RopGadget)
    stale.__setstate__(state)
    assert stale.has_endbr is False


def test_has_endbr_implies_endbr_bytes(cet_rop):
    g = cet_rop.analyze_gadget(ENDBR_GADGET)
    assert (not g.has_endbr) or cet_rop.arch.endbr_bytes is not None


# --------------------------------------------------------------------------- #
# C7 - legacy IBT enforcement (Builder._check_ibt)
# --------------------------------------------------------------------------- #
def _mk_gadget(addr, transit, has_endbr):
    g = RopGadget(addr)
    g.transit_type = transit
    g.has_endbr = has_endbr
    g.stack_change = 8
    g.bbl_addrs = [addr]
    return g


@pytest.fixture(scope="module")
def builder():
    p = angr.Project(NOCET_BIN, auto_load_libs=False)
    rop = p.analyses.ROP(cet=False)
    return rop, rop.chain_builder._reg_setter


def test_check_ibt_noop_when_off(builder):
    rop, b = builder
    rop.arch.ibt = False
    # even a violating pair must be a no-op when IBT is off (C0)
    b._check_ibt([_mk_gadget(0x1, "jmp_reg", False),
                  _mk_gadget(0x2, "pop_pc", False)])


def test_check_ibt_violation_raises(builder):
    rop, b = builder
    rop.arch.ibt = True
    try:
        with pytest.raises(RopException):
            b._check_ibt([_mk_gadget(0x1, "jmp_reg", False),
                          _mk_gadget(0x2, "pop_pc", False)])
    finally:
        rop.arch.ibt = False


def test_check_ibt_pass(builder):
    rop, b = builder
    rop.arch.ibt = True
    try:
        # jmp_reg -> endbr target is legal
        b._check_ibt([_mk_gadget(0x1, "jmp_reg", True),
                      _mk_gadget(0x2, "pop_pc", True)])
        # pop_pc is not an indirect branch, so the successor need not be endbr
        b._check_ibt([_mk_gadget(0x1, "pop_pc", False),
                      _mk_gadget(0x2, "pop_pc", False)])
    finally:
        rop.arch.ibt = False


# --------------------------------------------------------------------------- #
# C0 - legacy regression on a non-CET binary
# --------------------------------------------------------------------------- #
def test_noncet_detects_off():
    p = angr.Project(NOCET_BIN, auto_load_libs=False)
    rop = p.analyses.ROP()  # auto-detect
    assert rop.ibt is False and rop.shstk is False


@pytest.mark.slow
def test_legacy_set_regs_chain():
    # the legacy stack/ret path must still build a working chain with the new
    # code present (CET off -> all new branches inert)
    p = angr.Project(NOCET_BIN, auto_load_libs=False)
    rop = p.analyses.ROP(cet=False)
    rop.find_gadgets_single_threaded()
    chain = rop.set_regs(rdi=0x1337)
    state = chain.exec()
    assert state.solver.eval(state.regs.rdi) == 0x1337
