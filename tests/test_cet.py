"""
Phase 0 tests for the CET-resistant JOP/COP engine.

Covers contracts:
  C0 - legacy behavior preserved when CET is off / no note
  C1 - arch CET detection: apply_cet truth table, addr_has_endbr pure/total, ibt => endbr_bytes
  C2 - gadget has_endbr tagging (bool, endbr-aware, pickle/stale-cache survival)
  C7 - legacy-path IBT enforcement (Builder._check_ibt consecutive-pair gate)

The CET fixtures are *built at runtime* from the small C sources in tests/fixtures
(no binaries are committed). The whole module skips if no gcc with -fcf-protection
is available:
  - cet_probe : -fcf-protection=full  -> GNU property note advertises IBT+SHSTK
  - nocet     : -fcf-protection=none  -> no x86-feature note

Gadget addresses are discovered from symbols (add2/ident are tiny endbr-prefixed
leaf functions), never hardcoded.

The full C0 regression -- legacy stack/ret chains unchanged with this code present --
is covered by the whole existing `pytest tests/` suite running green; here we only
assert detection reads "off" on a non-CET binary.
"""
import os
import shutil
import pickle
import subprocess

import pytest
import angr
import angrop  # noqa: F401  pylint: disable=unused-import
from angrop.arch import get_arch
from angrop.errors import RopException
from angrop.rop_gadget import RopGadget

FIXTURES = os.path.join(os.path.dirname(os.path.realpath(__file__)), "fixtures")


# --------------------------------------------------------------------------- #
# runtime fixture builders
# --------------------------------------------------------------------------- #
def _gcc_supports_cf_protection():
    gcc = shutil.which("gcc")
    if not gcc:
        return False
    try:
        r = subprocess.run(
            [gcc, "-fcf-protection=full", "-xc", "-c", "-", "-o", os.devnull],
            input=b"int main(){return 0;}", capture_output=True, timeout=60)
        return r.returncode == 0
    except Exception:  # pylint: disable=broad-except
        return False


def _build(src, out, flags):
    gcc = shutil.which("gcc")
    cmd = [gcc, *flags, os.path.join(FIXTURES, src), "-o", out]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    if r.returncode != 0:
        pytest.skip("could not build %s: %s" % (src, r.stderr.decode()[:300]))
    return out


@pytest.fixture(scope="session")
def cet_bin(tmp_path_factory):
    if not _gcc_supports_cf_protection():
        pytest.skip("gcc with -fcf-protection not available")
    out = str(tmp_path_factory.mktemp("cet") / "cet_probe")
    return _build("cet_probe.c", out, ["-fcf-protection=full", "-O1", "-no-pie"])


@pytest.fixture(scope="session")
def nocet_bin(tmp_path_factory):
    if not shutil.which("gcc"):
        pytest.skip("gcc not available")
    out = str(tmp_path_factory.mktemp("nocet") / "nocet")
    return _build("nocet.c", out, ["-fcf-protection=none", "-O1", "-no-pie"])


def _arch(path):
    return get_arch(angr.Project(path, auto_load_libs=False))


def _endbr_entry(proj):
    """Entry of an endbr-prefixed leaf function (add2/ident); endbr64 is 4 bytes,
    so entry+4 is a non-endbr instruction-entry inside the same function."""
    sym = proj.loader.find_symbol("add2") or proj.loader.find_symbol("ident")
    assert sym is not None, "expected add2/ident symbol in cet_probe"
    return sym.rebased_addr


# --------------------------------------------------------------------------- #
# C1 - arch / CET detection
# --------------------------------------------------------------------------- #
def test_apply_cet_force_off(cet_bin):
    arch = _arch(cet_bin)
    arch.apply_cet(False)
    assert arch.ibt is False and arch.shstk is False


def test_apply_cet_force_on_x86(cet_bin):
    arch = _arch(cet_bin)
    arch.apply_cet(True)
    assert arch.ibt is True and arch.shstk is True


def test_apply_cet_autodetect_full(cet_bin):
    # cet_probe is compiled -fcf-protection=full -> note advertises IBT + SHSTK
    arch = _arch(cet_bin)
    ibt, shstk = arch.apply_cet(None)
    assert ibt is True and shstk is True


def test_apply_cet_autodetect_absent(nocet_bin):
    # nocet has no x86-feature note -> detection (note-based) must read CET off
    arch = _arch(nocet_bin)
    ibt, shstk = arch.apply_cet(None)
    assert ibt is False and shstk is False


def test_ibt_implies_endbr_bytes(cet_bin):
    # invariant: ibt => endbr_bytes is not None (only x86/amd64 can set ibt)
    arch = _arch(cet_bin)
    arch.apply_cet(True)
    assert (not arch.ibt) or arch.endbr_bytes is not None


def test_addr_has_endbr_true_false(cet_bin):
    proj = angr.Project(cet_bin, auto_load_libs=False)
    arch = get_arch(proj)
    arch.apply_cet(True)
    entry = _endbr_entry(proj)
    assert arch.addr_has_endbr(entry) is True
    # bytes just past the 4-byte endbr are not the opcode
    assert arch.addr_has_endbr(entry + 4) is False


def test_addr_has_endbr_total(cet_bin):
    # pure & total: never raises, always bool, even on unmapped/garbage addresses
    arch = _arch(cet_bin)
    arch.apply_cet(True)
    for addr in (0x0, 0xdeadbeef, 0xffffffffffffffff, -1):
        assert isinstance(arch.addr_has_endbr(addr), bool)


def test_addr_has_endbr_none_bytes_always_false(cet_bin):
    # endbr_bytes is None  =>  predicate is False for all inputs
    arch = _arch(cet_bin)
    arch.endbr_bytes = None
    for addr in (0x0, 0x401000, 0xdeadbeef):
        assert arch.addr_has_endbr(addr) is False


def test_apply_cet_force_on_non_x86_is_off():
    # cet=True on an arch without endbr support => stays off (+ warns), invariant holds
    p = angr.load_shellcode(b"\x00" * 8, arch="ARMEL")
    arch = get_arch(p)
    arch.apply_cet(True)
    assert arch.ibt is False and arch.shstk is False
    assert arch.endbr_bytes is None


# --------------------------------------------------------------------------- #
# C2 - gadget has_endbr tagging
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def cet_rop(cet_bin):
    proj = angr.Project(cet_bin, auto_load_libs=False)
    return proj.analyses.ROP(cet=True)


def test_rop_exposes_ibt_shstk(cet_rop):
    assert cet_rop.ibt is True and cet_rop.shstk is True


def test_gadget_has_endbr_true(cet_rop):
    entry = _endbr_entry(cet_rop.project)
    g = cet_rop.analyze_gadget(entry)
    assert g is not None, "endbr leaf function should analyze as a gadget"
    assert g.has_endbr is True
    # invariant: has_endbr => endbr_bytes is not None
    assert cet_rop.arch.endbr_bytes is not None


def test_gadget_has_endbr_false(cet_rop):
    # a gadget whose entry is *inside* the function (past the endbr) is not endbr
    entry = _endbr_entry(cet_rop.project)
    g = cet_rop.analyze_gadget(entry + 4)
    if g is None:
        pytest.skip("no analyzable gadget just past the endbr in this build")
    assert isinstance(g.has_endbr, bool)
    assert g.has_endbr is False


def test_setstate_stale_cache_defaults_false():
    # a gadget pickled before has_endbr existed must unpickle with has_endbr == False
    g = RopGadget(0x401865)
    state = g.__getstate__()
    state.pop("has_endbr", None)
    stale = RopGadget.__new__(RopGadget)
    stale.__setstate__(state)
    assert stale.has_endbr is False


def test_has_endbr_survives_pickle(cet_rop):
    entry = _endbr_entry(cet_rop.project)
    g = cet_rop.analyze_gadget(entry)
    g2 = pickle.loads(pickle.dumps(g))
    assert g2.has_endbr == g.has_endbr is True


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
def builder(nocet_bin):
    proj = angr.Project(nocet_bin, auto_load_libs=False)
    rop = proj.analyses.ROP(cet=False)
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
def test_noncet_detects_off(nocet_bin):
    rop = angr.Project(nocet_bin, auto_load_libs=False).analyses.ROP()  # auto-detect
    assert rop.ibt is False and rop.shstk is False
