import logging

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
        sc = max(gadget.stack_change, 0)
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
        cp = super().copy()
        cp = self.copy_effect(cp)
        cp.R = self.R
        cp._entry_addr = self._entry_addr
        return cp
