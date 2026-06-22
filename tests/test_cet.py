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
    # only force CET off when the toolchain knows the flag (needed on hardened
    # distros that default to -fcf-protection=full); otherwise plain gcc is already
    # non-CET, so we can still build the fixture instead of skipping the C0/C1 tests.
    flags = ["-O1", "-no-pie"]
    if _gcc_supports_cf_protection():
        flags = ["-fcf-protection=none", *flags]
    return _build("nocet.c", out, flags)


@pytest.fixture(scope="session")
def jop_bin(tmp_path_factory):
    if not _gcc_supports_cf_protection():
        pytest.skip("gcc with -fcf-protection not available")
    out = str(tmp_path_factory.mktemp("jop") / "jop_gadgets")
    return _build("jop_gadgets.c", out, ["-fcf-protection=full", "-O0", "-no-pie"])


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


def test_stale_cache_retagged_on_load(cet_bin):
    # a gadget cache pickled before has_endbr existed loads with has_endbr=False on
    # every gadget; on an IBT binary that must be re-tagged from the binary at load
    # time, not left False (else false IBT violations / dropped shifters). C2.
    proj = angr.Project(cet_bin, auto_load_libs=False)
    rop = proj.analyses.ROP(cet=True)
    entry = _endbr_entry(proj)
    g = rop.analyze_gadget(entry)
    assert g is not None and g.has_endbr is True

    # simulate a stale cache entry: tag cleared (as the old default would leave it)
    g.has_endbr = False
    g.project = None

    # load through a FRESH project/analysis, mirroring real load_gadgets usage in a
    # new process (avoids angr's per-project analysis cache returning `rop` again)
    proj2 = angr.Project(cet_bin, auto_load_libs=False)
    rop2 = proj2.analyses.ROP(cet=True)
    # isolate the has_endbr (IBT) retag path from the dispatcher-cache (shstk) guard;
    # has_endbr re-tagging applies on IBT-only binaries too. The 2-tuple here also
    # exercises backward-compat loading of a pre-3-tuple cache.
    rop2.arch.shstk = False
    rop2._load_cache_tuple(([g], {}))
    assert g.has_endbr is True, "load must re-tag has_endbr from the binary"


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


# --------------------------------------------------------------------------- #
# C3 - dispatcher classification + is_functional predicate
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def jop_rop(jop_bin):
    proj = angr.Project(jop_bin, auto_load_libs=False)
    return proj.analyses.ROP(cet=True)  # shstk=True -> dispatcher tagging active


def _g(rop, name):
    return rop.analyze_gadget(rop.project.loader.find_symbol(name).rebased_addr)


@pytest.mark.parametrize("name,reg,disp,stride", [
    ("g_disp", "rbp", 0, 8),       # add rbp,8; jmp [rbp-8]  -> delta = s-c = 0
    ("g_disp_c0", "rbp", 8, 8),    # add rbp,8; jmp [rbp]    -> delta = s   = 8
    ("g_disp_sub", "rbp", 0, -8),  # sub rbp,8; jmp [rbp+8]  -> negative stride
])
def test_dispatcher_detect(jop_rop, name, reg, disp, stride):
    g = _g(jop_rop, name)
    assert g is not None
    assert g.is_dispatcher is True
    assert g.dispatch_reg == reg
    assert g.dispatch_disp == disp
    assert g.dispatch_stride == stride
    # C3 invariant
    assert g.transit_type == "jmp_mem" and g.has_endbr and not g.has_conditional_branch
    assert g.dispatch_stride != 0


def test_dispatcher_rejects_non_transparent(jop_rop):
    # g_clobber also writes rcx, so changed_regs is not a subset of {Rd}
    g = _g(jop_rop, "g_clobber")
    assert g is not None and g.transit_type == "jmp_mem"
    assert g.is_dispatcher is False


def test_dispatcher_rejects_jmp_reg(jop_rop):
    g = _g(jop_rop, "g_pop_rdi")  # functional gadget, not a dispatcher
    assert g is not None and g.is_dispatcher is False


def test_dispatcher_tagging_gated_on_cet_forced(jop_bin):
    # JOP classification/routing is gated on cet_forced (cet=True opt-in), NOT on
    # auto-detected shstk -- a binary merely being CET-compiled must stay legacy so
    # ROP-building on CET binaries is unaffected (C0). jop_bin HAS the CET note.
    proj = angr.Project(jop_bin, auto_load_libs=False)

    # cet=False: forced off -> not tagged
    rop_off = proj.analyses.ROP(cet=False)
    assert _g(rop_off, "g_disp").is_dispatcher is False
    assert rop_off.arch.cet_forced is False

    # cet=None on a CET binary: shstk is DETECTED but NOT forced -> still legacy,
    # dispatcher not tagged (this is the regression guard for the C9 routing gate)
    rop_auto = angr.Project(jop_bin, auto_load_libs=False).analyses.ROP(cet=None)
    assert rop_auto.shstk is True and rop_auto.arch.cet_forced is False
    assert _g(rop_auto, "g_disp").is_dispatcher is False


def test_cache_built_without_cet_warns_not_raises(jop_bin, tmp_path, caplog):
    # a cache built with CET off has no dispatcher tags (can't be recomputed on load).
    # loading it under shstk must NOT raise -- legacy ROP still works -- but must warn
    # so a later JOP build's "no dispatcher" isn't a surprise.
    import logging
    proj = angr.Project(jop_bin, auto_load_libs=False)
    rop_off = proj.analyses.ROP(cet=False)
    rop_off.find_gadgets_single_threaded()
    cache = str(tmp_path / "nocet.cache")
    rop_off.save_gadgets(cache)

    proj2 = angr.Project(jop_bin, auto_load_libs=False)
    rop_on = proj2.analyses.ROP(cet=True)  # shstk active
    with caplog.at_level(logging.WARNING, logger="angrop.rop"):
        rop_on.load_gadgets(cache, optimize=False)  # must not raise
    assert any("without CET" in r.message for r in caplog.records)
    # documented consequence: the load carries no dispatcher tags
    assert all(not g.is_dispatcher for g in rop_on._all_gadgets)


def test_is_functional_truth_table(jop_rop):
    pop_rdi = _g(jop_rop, "g_pop_rdi")  # endbr; pop rdi; jmp rbx
    assert pop_rdi.is_functional("rbx", "rbp") is True
    # wrong return register
    assert pop_rdi.is_functional("rax", "rbp") is False
    # dispatch reg clobbered (rdi is popped/changed)
    assert pop_rdi.is_functional("rbx", "rdi") is False
    # the dispatcher itself is jmp_mem, never functional
    disp = _g(jop_rop, "g_disp")
    assert disp.is_functional("rbx", "rbp") is False


# --------------------------------------------------------------------------- #
# C4 - FunctionalBlock effect-equivalence (NOT a RopBlock)
# --------------------------------------------------------------------------- #
def test_functional_block_effect_equiv(jop_rop):
    from angrop.jop_chain import FunctionalBlock
    from angrop.rop_block import RopBlock

    builder = jop_rop.chain_builder._reg_setter
    func = _g(jop_rop, "g_pop_rdi")        # endbr; pop rdi; jmp rbx   (R = rbx)
    twin = _g(jop_rop, "g_pop_rdi_ret")    # endbr; pop rdi; ret       (ret-twin)
    assert func.transit_type == "jmp_reg" and twin.transit_type == "pop_pc"

    fb = FunctionalBlock.from_gadget(func, builder, "rbx")

    # type invariant: a FunctionalBlock is never a RopBlock (C4)
    assert not isinstance(fb, RopBlock)
    # no conditional branches survived analysis (C4 post)
    assert not fb.branch_dependencies

    # transit-agnostic register/memory effects match the ret-twin
    assert {p.reg for p in fb.reg_pops} == {p.reg for p in twin.reg_pops} == {"rdi"}
    assert fb.changed_regs == twin.changed_regs == {"rdi"}
    assert fb.reg_moves == twin.reg_moves == []
    assert fb.concrete_regs == twin.concrete_regs

    # the only difference is the ret's pc-pop word: twin.stack_change is one word more
    assert twin.stack_change - fb.stack_change == jop_rop.project.arch.bytes
    assert fb.stack_change == func.stack_change  # block matches its single gadget here


# --------------------------------------------------------------------------- #
# C5/C6 (Phase 2 gate) - a hand-built JOP sequence reaches its goal state
# --------------------------------------------------------------------------- #
def test_jop_chain_exec_reaches_goal(jop_rop):
    from angrop.jop_chain import JopChain

    builder = jop_rop.chain_builder._reg_setter
    D = _g(jop_rop, "g_disp")  # dispatcher: add rbp,8; jmp [rbp-8]  (delta=0, stride=8)
    assert D.is_dispatcher and D.dispatch_reg == "rbp"
    F0 = jop_rop.project.loader.find_symbol("g_pop_rdi").rebased_addr  # pop rdi; jmp rbx

    table_ptr = 0x500000
    chain = JopChain(jop_rop.project, builder, D, "rbx", table_ptr, [F0])
    target = 0x4141414242424343
    chain.add_value(target)  # the value pop rdi pulls off the stack

    final = chain.exec()
    # goal: rdi holds the popped value, and we are ret-free (ended back at the dispatcher)
    assert final.solver.eval(final.regs.rdi) == target
    assert final.solver.eval(final.regs.rip) == D.addr

    # bootstrap preconditions are surfaced, not hidden
    setup = chain.setup()
    assert setup["entry_pc"] == D.addr
    assert setup["initial_regs"]["rbp"] == table_ptr - 0  # Rd = table_ptr - delta
    assert setup["initial_regs"]["rbx"] == D.addr         # R = D.addr
    assert setup["table_addrs"] == [F0]


def test_jop_build_path_solves_set_rdi(jop_rop):
    # C5: the JOP build path SOLVES for the stack pop-data given a target register
    # value (vs the hand-built concrete value above), reusing the shared solving core.
    from angrop.rop_value import RopValue

    builder = jop_rop.chain_builder._reg_setter
    D = _g(jop_rop, "g_disp")
    F0 = _g(jop_rop, "g_pop_rdi")  # the RopGadget (pop rdi; jmp rbx)
    table_ptr = 0x500000
    target = 0x4142434445464748
    register_dict = {"rdi": RopValue(target, jop_rop.project)}

    chain = builder._build_jop_chain([F0], D, "rbx", table_ptr, register_dict)
    assert chain.table_addrs == [F0.addr]

    final = chain.exec()
    assert final.solver.eval(final.regs.rdi) == target   # solver found the pop-data
    assert final.solver.eval(final.regs.rip) == D.addr   # ret-free, back at the dispatcher


def test_jop_chain_and_functionalblock_copy(jop_rop):
    # copy() must not crash (RopChain.copy reconstructs via a 2-arg ctor; the JOP
    # subclasses need extra positional args)
    from angrop.jop_chain import JopChain, FunctionalBlock

    builder = jop_rop.chain_builder._reg_setter
    D = _g(jop_rop, "g_disp")
    F = _g(jop_rop, "g_pop_rdi")

    fb2 = FunctionalBlock.from_gadget(F, builder, "rbx").copy()
    assert fb2.R == "rbx" and fb2.changed_regs == {"rdi"}

    jc = JopChain(jop_rop.project, builder, D, "rbx", 0x500000, [F.addr])
    jc.add_value(0x4142434445464748)
    jc2 = jc.copy()
    assert jc2.dispatcher is D and jc2.table_addrs == [F.addr]
    final = jc2.exec()
    assert final.solver.eval(final.regs.rdi) == 0x4142434445464748


def test_jop_build_rejects_machinery_regs(jop_rop):
    from angrop.rop_value import RopValue

    builder = jop_rop.chain_builder._reg_setter
    D = _g(jop_rop, "g_disp")
    F0 = _g(jop_rop, "g_pop_rdi")
    # requesting Rd (rbp) or R (rbx) as a chain target must raise cleanly, not fail
    # confusingly inside the solving core
    with pytest.raises(RopException):
        builder._build_jop_chain([F0], D, "rbx", 0x500000, {"rbp": RopValue(0, jop_rop.project)})
    with pytest.raises(RopException):
        builder._build_jop_chain([F0], D, "rbx", 0x500000, {"rbx": RopValue(0, jop_rop.project)})


def test_jop_chain_dstr_is_structured(jop_rop):
    # presentation must show the table mechanism, not a misleading flat stack view
    from angrop.jop_chain import JopChain

    builder = jop_rop.chain_builder._reg_setter
    D = _g(jop_rop, "g_disp")
    F0 = _g(jop_rop, "g_pop_rdi")
    jc = JopChain(jop_rop.project, builder, D, "rbx", 0x500000, [F0.addr])
    s = jc.dstr()
    assert "JOP" in s and "dispatch table" in s and f"{0x500000:#x}" in s
    assert jc.payload_code() == s


@pytest.fixture(scope="module")
def jop_rop_full(jop_bin):
    # full gadget discovery so chain_builder.gadgets holds the dispatcher + functional pool
    proj = angr.Project(jop_bin, auto_load_libs=False)
    rop = proj.analyses.ROP(cet=True)
    rop.find_gadgets_single_threaded()
    return rop


def test_jop_set_regs_end_to_end(jop_rop_full):
    # C9 gate: under shstk, rop.set_regs routes to the JOP orchestrator, which selects
    # a (D, R), searches the functional pool, and emits a ret-free JopChain.
    from angrop.jop_chain import JopChain

    rop = jop_rop_full
    chain = rop.set_regs(rdi=0x4141414141414141, rsi=0x4242424242424242)
    assert isinstance(chain, JopChain)

    final = chain.exec()
    assert final.solver.eval(final.regs.rdi) == 0x4141414141414141
    assert final.solver.eval(final.regs.rsi) == 0x4242424242424242
    # ret-free: control ended back at the dispatcher, and every table entry is endbr (C6)
    assert final.solver.eval(final.regs.rip) == chain.dispatcher.addr
    for addr in chain.table_addrs:
        g = next(g for g in rop.rop_gadgets if g.addr == addr)
        assert g.has_endbr and g.is_functional(chain.R, chain.dispatch_reg)


def test_jop_negative_stride_table_within_reserved(jop_rop_full):
    # a sub-based dispatcher has a negative stride; the table grows downward, so the
    # reserved region must cover the entries (regression: the base wasn't offset, so
    # entries landed below table_ptr, outside the reserved/zeroed window)
    from angrop.chain_builder.builder import Builder

    js = jop_rop_full.chain_builder._jop_setter
    bytes_per = jop_rop_full.project.arch.bytes
    for n, stride in ((3, 8), (3, -8)):
        before = list(Builder.used_writable_ptrs)
        tp = js._alloc_table_ptr(n, stride)
        new = [x for x in Builder.used_writable_ptrs if x not in before]
        assert len(new) == 1
        base, span = new[0]
        for k in range(n):  # every entry must fit inside the reserved [base, base+span)
            entry = tp + k * stride
            assert base <= entry and entry + bytes_per <= base + span


def test_jop_chain_fails_closed_on_stack_apis(jop_rop):
    from angrop.jop_chain import JopChain

    builder = jop_rop.chain_builder._reg_setter
    D = _g(jop_rop, "g_disp")
    F0 = jop_rop.project.loader.find_symbol("g_pop_rdi").rebased_addr
    chain = JopChain(jop_rop.project, builder, D, "rbx", 0x500000, [F0])
    # JOP chains are not flat stack payloads -- these must raise, not silently corrupt
    with pytest.raises(RopException):
        chain.payload_str()
    with pytest.raises(RopException):
        chain.payload_bv()
    with pytest.raises(RopException):
        _ = chain + chain
