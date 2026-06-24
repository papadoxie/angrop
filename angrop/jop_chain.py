import logging

import claripy

from .rop_chain import RopChain
from .rop_block import RopBlock
from .rop_effect import RopEffect
from .rop_gadget import RopGadget
from .errors import RopException
from . import rop_utils

l = logging.getLogger(__name__)


class FunctionalBlock(RopChain, RopEffect):
    """
    An effect-cached unit for the JOP path, analogous to RopBlock but on a different
    substrate. It is deliberately **NOT** a RopBlock: a RopBlock takes its PC from the
    stack patch (the `ret`/`pop_pc` mechanism), whereas a FunctionalBlock takes its PC
    from the dispatcher register `R` and ends in `jmp R`. It must therefore never be
    composed via the stack-slot `__add__`/`next_pc` machinery — composition is
    table-based (handled by JopChain/the JOP builder).

    What it DOES reuse is RopBlock's role-1, transit-agnostic *effect analysis*: it runs
    the same `_analyze_effect` helper pipeline so its effect attributes (`popped_regs`,
    `changed_regs`, `concrete_regs`, `reg_moves`, `stack_change`, ...) are populated
    identically and it drops into the reg-setting graph search as an ordinary edge.
    The only execution difference from RopBlock is the entry: `ip = gadget.addr` rather
    than `ip = stack_pop()` (there is no PC on the stack), and the terminal transit is
    `jmp R` (unconstrained in isolation, since `R` is symbolic here). (C4)
    """

    def __init__(self, project, builder, R, state=None, badbytes=None):
        RopChain.__init__(self, project, builder, state=state, badbytes=badbytes)
        RopEffect.__init__(self)
        # the dispatcher return register this block transfers through (`jmp R`)
        self.R = R
        # entry IP -- the first functional gadget's address (no stack_pop entry)
        self._entry_addr = None

    def sim_exec(self):
        """
        Like RopBlock.sim_exec but entry is the gadget address, not a stack pop. The
        terminal `jmp R` lands on the symbolic `R` here, so the final state is the lone
        unconstrained successor (same shape RopBlock's effect helpers expect).
        """
        project = self._p
        state = self._blank_state.copy()
        for idx, val in enumerate(self._values):
            offset = idx * project.arch.bytes
            state.memory.store(state.regs.sp + offset, val.data, project.arch.bytes,
                               endness=project.arch.memory_endness)
        state.ip = self._entry_addr  # NOT stack_pop -- PC is not on the stack

        simgr = project.factory.simgr(state, save_unconstrained=True)
        while simgr.active:
            simgr.step()
            if len(simgr.active + simgr.unconstrained) != 1:
                l.warning("fail to sim_exec FunctionalBlock:\n%s", self.dstr())
                raise RopException("fail to sim_exec FunctionalBlock")
        final_state = simgr.unconstrained[0]
        return state, final_state

    def _analyze_effect(self):
        """Run the same transit-agnostic effect-extraction helpers as
        RopBlock._analyze_effect, on this block's no-stack-pop execution (C4)."""
        init_state, final_state = self.sim_exec()
        ga = self._builder._gadget_analyzer

        self.clear_effect()
        ga._compute_sp_change(init_state, final_state, self)
        ga._check_reg_changes(final_state, init_state, self)
        ga._check_reg_change_dependencies(init_state, final_state, self)
        ga._check_reg_movers(init_state, final_state, self)
        ga._check_pop_equal_set(self, final_state)
        ga._analyze_concrete_regs(final_state, self)
        ga._analyze_mem_access(final_state, init_state, self)

        self.bbl_addrs = list(final_state.history.bbl_addrs)
        project = init_state.project
        self.isn_count = sum(project.factory.block(a).instructions for a in self.bbl_addrs)

        ga._cond_branch_analysis(self, final_state)
        if self.branch_dependencies:
            raise RopException("FunctionalBlock must not have conditional branches")

    @staticmethod
    def from_gadget(gadget, builder, R):
        """
        Build a FunctionalBlock from a single functional gadget (`...; jmp R`). The
        gadget address is a dispatch-table entry (a precondition), NOT a stack value, so
        `_values` holds only the symbolic stack pop-data the gadget consumes.
        """
        assert isinstance(gadget, RopGadget)
        assert gadget.transit_type == 'jmp_reg'           # C4 pre
        assert gadget.has_endbr
        assert not gadget.has_conditional_branch
        assert R not in gadget.changed_regs

        project = builder.project
        bytes_per_pop = project.arch.bytes
        # size the symbolic stack like _build_jop_chain: include out-of-patch reads
        # (max_stack_offset), not just what the gadget pops, so a gadget that reads deeper
        # than it pops still lands on symbolic stack and re-derives correct effects
        sc = max(gadget.stack_change, gadget.max_stack_offset + bytes_per_pop, 0)
        state = rop_utils.make_symbolic_state(project, builder.arch.reg_list,
                                              sc // bytes_per_pop)
        state.ip = gadget.addr

        fb = FunctionalBlock(project, builder, R, state=state, badbytes=builder.badbytes)
        fb._entry_addr = gadget.addr
        for offset in range(0, sc, bytes_per_pop):
            sym_word = state.stack_read(offset, bytes_per_pop)
            fb.add_value(rop_utils.cast_rop_value(sym_word, project))
        fb.set_gadgets([gadget])
        fb._analyze_effect()

        # type invariant (C4): a FunctionalBlock is never a RopBlock
        assert not isinstance(fb, RopBlock)
        return fb

    def copy(self):
        # NOT via super().copy(): RopChain.copy() reconstructs with the 2-arg
        # (project, builder) constructor, but FunctionalBlock.__init__ needs `R`.
        # Construct correctly, then mirror RopChain.copy()'s state copy + effect copy.
        cp = FunctionalBlock(self._p, self._builder, self.R)
        cp._gadgets = list(self._gadgets)
        cp._values = list(self._values)
        cp.payload_len = self.payload_len
        cp._blank_state = self._blank_state.copy()
        cp.badbytes = self.badbytes
        cp._sigreturn_frame = self._sigreturn_frame
        cp._pivoted = self._pivoted
        cp._init_sp = self._init_sp
        cp._entry_addr = self._entry_addr
        self.copy_effect(cp)
        return cp


class JopChain(RopChain):
    """
    A ret-free JOP chain. Unlike a RopChain it is **not** a flat stack payload: control
    flows through an in-memory dispatch table `D -> F0 -> D -> F1 -> ...` (the
    attacker-staged precondition), while the ordinary stack carries only pop-data. It
    therefore overrides exec/presentation and *fails closed* on the stack-composition
    APIs (payload_str/payload_bv/__add__) that would silently corrupt it.

    The bootstrap the attacker must stage (surfaced via `setup()`): entry pc = D, the
    initial registers (`Rd = table_ptr - delta`, `R = D.addr`), and the dispatch table
    `[F0, F1, ...]` laid at `table_ptr` at stride `s`. Only `mem_writes` (data like
    "/bin/sh") are written by the chain itself.
    """

    def __init__(self, project, builder, dispatcher, R, table_ptr, table_addrs,
                 state=None, badbytes=None, terminal=False):
        super().__init__(project, builder, state=state, badbytes=badbytes)
        self.dispatcher = dispatcher                  # the dispatcher RopGadget D
        self.R = R                                    # return register (holds D.addr)
        self.dispatch_reg = dispatcher.dispatch_reg   # Rd
        self.stride = dispatcher.dispatch_stride      # s
        self.dispatch_disp = dispatcher.dispatch_disp # delta
        self.table_ptr = table_ptr                    # where the table is staged
        self.table_addrs = list(table_addrs)          # ordered functional gadget addrs
        # terminal: the last table entry does NOT return to D (e.g. a syscall); exec stops
        # at its entry so the requested registers are read right before it runs (C9 syscall)
        self.terminal = terminal
        self.mem_writes = []                          # chain-written data: (addr, bv)

    @property
    def initial_regs(self):
        """bootstrap register preconditions: Rd = table_ptr - delta, R = D.addr"""
        return {self.dispatch_reg: self.table_ptr - self.dispatch_disp,
                self.R: self.dispatcher.addr}

    def _stage_state(self):
        """build the entry state: stage the table + data, set the bootstrap registers,
        enter at D, and lay the stack pop-data. No stack_pop entry (P1)."""
        project = self._p
        bits = project.arch.bits
        arch_bytes = project.arch.bytes
        endness = project.arch.memory_endness
        state = self._blank_state.copy()

        # stage the dispatch table -- a precondition, NOT a chain mem_write (P1/C9)
        for k, addr in enumerate(self.table_addrs):
            state.memory.store(self.table_ptr + k * self.stride,
                               claripy.BVV(addr, bits), endness=endness)
        # data the chain writes (e.g. "/bin/sh", argv); empty until Phase 3
        for waddr, wdata in self.mem_writes:
            state.memory.store(waddr, wdata, endness=endness)
        # bootstrap registers Rd, R
        for reg, val in self.initial_regs.items():
            state.registers.store(reg, claripy.BVV(val % (1 << bits), bits))
        state.ip = self.dispatcher.addr
        # lay stack pop-data (ordinary stack, allowed under CET)
        for idx, val in enumerate(self._values):
            state.memory.store(state.regs.sp + idx * arch_bytes, val.data, arch_bytes,
                               endness=endness)
        return state

    def exec(self, timeout=None): # pylint: disable=arguments-differ
        """
        Symbolically execute the JOP chain. Control is concrete for a fixed (D, R):
        `jmp R` -> D, and D's `jmp [Rd-c]` -> the next concrete table entry. So every
        step yields exactly one successor (C6.6, fail-closed on any fork), and stepping
        is explicitly bounded to the n functional gadgets -- it would otherwise run off
        the end of the table.

        For a terminal chain (a syscall) the last table entry does not return to D; stepping
        stops at its entry, so the returned state holds the registers right before it runs.
        """
        project = self._p
        state = self._stage_state()
        D = self.dispatcher.addr
        n = len(self.table_addrs)
        terminal_addr = self.table_addrs[-1] if self.terminal else None

        simgr = project.factory.simgr(state, save_unconstrained=True)
        returns_to_D = 0          # number of functional gadgets that have returned to D
        steps = 0
        budget = 8 * n + 16       # generous bound for multi-block functional gadgets
        cur = state
        while True:
            if self.terminal:
                if cur.solver.eval(cur.regs.ip) == terminal_addr:
                    break
            elif returns_to_D >= n:
                break
            simgr.step()
            steps += 1
            succs = simgr.active + simgr.unconstrained
            if len(succs) != 1:
                raise RopException("JOP exec: step did not yield a single successor")
            cur = succs[0]
            if cur.solver.eval(cur.regs.ip) == D:
                returns_to_D += 1
            if steps > budget:
                raise RopException("JOP exec exceeded step budget")
        return cur

    def setup(self):
        """
        The structured bootstrap the attacker must stage (instead of a flat buffer):
        entry pc, initial registers, the dispatch table, stride, and chain mem-writes.
        """
        return {
            "entry_pc": self.dispatcher.addr,
            "initial_regs": self.initial_regs,
            "table_ptr": self.table_ptr,
            "table_addrs": list(self.table_addrs),
            "stride": self.stride,
            "mem_writes": list(self.mem_writes),
        }

    def dstr(self):
        """
        Structured JOP representation -- the dispatch table, the bootstrap registers, and
        the stack pop-data. Overrides RopChain.dstr (which assumes _values are on-stack
        gadget addresses) so str()/printing a JopChain doesn't emit a misleading flat
        stack view that hides the entire table mechanism.
        """
        lines = ["# ret-free JOP chain (composes via the dispatch table, not the stack)",
                 "# attacker-staged bootstrap:",
                 f"#   entry pc = {self.dispatcher.addr:#x}"]
        for reg, val in self.initial_regs.items():
            lines.append(f"#   {reg} = {val:#x}")
        lines.append(f"# dispatch table @ {self.table_ptr:#x} (stride {self.stride:#x}):")
        for k, addr in enumerate(self.table_addrs):
            asm = self.addr_to_asmstring(addr)
            lines.append(f"#   table[{k}] = {addr:#x}" + (f"  ; {asm}" if asm else ""))
        if self.mem_writes:
            lines.append("# chain-written data:")
            for addr, data in self.mem_writes:
                lines.append(f"#   [{addr:#x}] = {data!r}")
        lines.append("# stack pop-data:")
        for v in self._values:
            if v.symbolic:
                # solve under the chain constraints (which include badbyte avoidance) so
                # the displayed pop-data is the concrete, badbyte-free bytes to stage
                lines.append(f"#   {self._blank_state.solver.eval(v.data):#x}")
            else:
                lines.append(f"#   {v.concreted:#x}")
        return "\n".join(lines) + "\n"

    def payload_code(self, *args, **kwargs): # pylint: disable=arguments-differ
        """JOP chains are not a flat buffer; present the structured bootstrap instead."""
        return self.dstr()

    # ----- fail closed on stack-composition APIs (would silently corrupt a JOP chain) -----
    _JOP_NO_STACK = ("JOP chains are not a flat stack payload and compose via the dispatch "
                     "table, not stack-splicing; use payload_code()/setup()")

    def payload_str(self, *args, **kwargs):
        raise RopException(self._JOP_NO_STACK)

    def payload_bv(self):
        raise RopException(self._JOP_NO_STACK)

    def __add__(self, other):
        raise RopException(self._JOP_NO_STACK)

    def copy(self):
        # NOT via super().copy(): RopChain.copy() reconstructs with the 2-arg
        # (project, builder) constructor, but JopChain.__init__ needs the dispatcher,
        # R, table_ptr and table_addrs. Construct correctly, then mirror RopChain.copy().
        cp = JopChain(self._p, self._builder, self.dispatcher, self.R, self.table_ptr,
                      list(self.table_addrs), terminal=self.terminal)
        cp._gadgets = list(self._gadgets)
        cp._values = list(self._values)
        cp.payload_len = self.payload_len
        cp._blank_state = self._blank_state.copy()
        cp.badbytes = self.badbytes
        cp._sigreturn_frame = self._sigreturn_frame
        cp._pivoted = self._pivoted
        cp._init_sp = self._init_sp
        cp.mem_writes = list(self.mem_writes)
        return cp
