import logging

from .builder import Builder
from ..errors import RopException
from .. import rop_utils

l = logging.getLogger(__name__)


class JopSetter(Builder):
    """
    Orchestrates ret-free JOP register-setting (C9). For a requested register dict it:
      1. picks a dispatcher D (with Rd, stride, delta) and a return register R, best-first
         and capped at N_D dispatchers so the register plane stays O(N);
      2. builds the functional gadget pool for that (D, R) -- gadgets `is_functional(R, Rd)`
         relevant to the targets (so the pool is (D,R)-specific and a failed (D,R) cleanly
         falls through to the next);
      3. reuses the reg-setter's transit-agnostic giga-graph search over that pool to find
         a functional gadget sequence [F0..Fn];
      4. emits a JopChain via _build_jop_chain (the dispatch table is a precondition, P1)
         and verifies exec() reaches the goal state.
    """
    N_D = 8  # cap on dispatcher candidates (keeps the register plane O(N), per the plan)

    def bootstrap(self):
        pass

    def optimize(self, processes): # pylint: disable=unused-argument
        return False

    def _effect_tuple(self, g):
        raise NotImplementedError("JopSetter does not use _effect_tuple")

    def _comparison_tuple(self, g):
        raise NotImplementedError("JopSetter does not use _comparison_tuple")

    # ------------------------------------------------------------------ #
    def _dispatchers(self):
        disps = [g for g in self.chain_builder.gadgets if getattr(g, "is_dispatcher", False)]
        # rank cheap-first (fewer instructions, smaller stride), cap at N_D
        disps.sort(key=lambda d: ((d.isn_count or 0), abs(d.dispatch_stride or 0)))
        return disps[:self.N_D]

    def _candidate_dr(self):
        """yield (D, R) candidates best-first, R != Rd, R not clobbered by D, R != sp (C8)."""
        sp = self.arch.stack_pointer
        for d in self._dispatchers():
            rd = d.dispatch_reg
            for r in self.arch.reg_list:
                if r == rd or r == sp or r in d.changed_regs:
                    continue
                yield d, r

    def _functional_pool(self, r, rd, target_regs):
        """functional gadgets (is_functional(R, Rd)) that can affect a target register."""
        pool = []
        for g in self.chain_builder.gadgets:
            if not g.is_functional(r, rd):
                continue
            if any(reg in g.popped_regs or reg in g.changed_regs or reg in g.concrete_regs
                   or reg in g.reg_dependencies for reg in target_regs):
                pool.append(g)
        return pool

    def _alloc_table_ptr(self, n, stride):
        """
        Reserve a badbyte-free region for an n-entry dispatch table at `stride` and return
        the address of table[0]. Entries are staged at table_ptr + k*stride (k=0..n-1); for
        a negative stride (a `sub Rd,s` dispatcher) the table grows downward, so table[0]
        sits at the HIGH end of the reserved region (otherwise the entries would land below
        table_ptr, outside the reserved/zeroed window).
        """
        bytes_per = self.project.arch.bytes
        span = (n - 1) * abs(stride) + bytes_per
        base = self._get_ptr_to_writable(span)
        return base if stride > 0 else base + (n - 1) * abs(stride)

    def run(self, modifiable_memory_range=None, preserve_regs=None, warn=True, **registers): # pylint: disable=unused-argument
        return self.set_regs(preserve_regs=preserve_regs, **registers)

    def set_regs(self, preserve_regs=None, **registers):
        if not registers:
            from ..rop_chain import RopChain # pylint: disable=import-outside-toplevel
            return RopChain(self.project, self.chain_builder, badbytes=self.badbytes)

        preserve_regs = set(preserve_regs) if preserve_regs else set()
        rop_regs = {r: rop_utils.cast_rop_value(v, self.project) for r, v in registers.items()}
        target_regs = set(registers)
        rs = self.chain_builder._reg_setter

        for d, r in self._candidate_dr():
            rd = d.dispatch_reg
            pool = self._functional_pool(r, rd, target_regs)
            if not pool:
                continue
            accept = lambda g, _r=r, _rd=rd: g.is_functional(_r, _rd)
            try:
                # handle_hard=False: hard-reg handling consults the legacy self_contained
                # _reg_setting_dict, which never holds functional gadgets (would misfire)
                seqs = rs.find_candidate_chains_giga_graph_search(
                    None, dict(rop_regs), preserve_regs, False,
                    gadgets=pool, accept=accept, handle_hard=False)
            except RopException:
                continue
            for seq in seqs:
                if not seq:
                    continue
                used_before = list(Builder.used_writable_ptrs)
                try:
                    table_ptr = self._alloc_table_ptr(len(seq), d.dispatch_stride)
                    chain = self._build_jop_chain(list(seq), d, r, table_ptr, dict(rop_regs))
                    if self._verify(chain, rop_regs):
                        return chain
                except RopException:
                    pass
                # release any writable region this failed attempt reserved (a successful
                # attempt returns above and keeps its table reservation)
                Builder.used_writable_ptrs[:] = used_before
        raise RopException("JOP: couldn't set registers with the available "
                           "dispatcher/functional gadgets")

    def _verify(self, chain, rop_regs):
        """exec() the JOP chain and confirm every concrete target register holds its value
        and control ended ret-free back at the dispatcher (C6)."""
        final = chain.exec()
        if final.solver.eval(final.regs.ip) != chain.dispatcher.addr:
            return False
        for reg, val in rop_regs.items():
            if val.symbolic:
                continue
            if final.solver.eval(final.registers.load(reg)) != val.concreted:
                return False
        return True
