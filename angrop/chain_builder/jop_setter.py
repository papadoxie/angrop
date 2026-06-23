import logging

from .builder import Builder
from ..errors import RopException
from ..rop_value import RopValue
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

    def _build_for(self, reg_targets, terminals=(), preserve_regs=None, verify_fn=None):
        """
        Core JOP builder shared by the data-plane primitives. For each (D, R) best-first:
        set `reg_targets` via the giga-graph search over the functional pool, append the
        `terminals` (functional gadgets that perform the primitive's operation -- e.g. a
        store or a non-terminal syscall; each must be is_functional(R, Rd) so it returns
        to D), build a JopChain, and accept it if `verify_fn(chain)` confirms the goal
        (default: the requested registers hold their values).
        """
        preserve_regs = set(preserve_regs) if preserve_regs else set()
        # the cet_forced route bypasses the legacy boundary checks, so a bad value type or
        # an invalid register-name value would surface as a bare ValueError; normalize to
        # RopException at this public boundary
        try:
            rop_regs = {r: rop_utils.cast_rop_value(v, self.project) for r, v in reg_targets.items()}
        except ValueError as e:
            raise RopException(str(e)) from e
        target_regs = set(reg_targets)
        terminals = list(terminals)
        if verify_fn is None:
            verify_fn = lambda chain: self._verify_regs(chain, rop_regs)
        rs = self.chain_builder._reg_setter

        for d, r in self._candidate_dr():
            rd = d.dispatch_reg
            # can't set the dispatch machinery regs, and every terminal must transfer via
            # `jmp R` (functional) for this (D, R)
            if target_regs & {r, rd}:
                continue
            if not all(t.is_functional(r, rd) for t in terminals):
                continue
            try:
                if target_regs:
                    pool = self._functional_pool(r, rd, target_regs)
                    if not pool:
                        continue
                    accept = lambda g, _r=r, _rd=rd: g.is_functional(_r, _rd)
                    # handle_hard=False: hard-reg handling consults the legacy
                    # self_contained _reg_setting_dict, which never holds functional gadgets
                    seqs = rs.find_candidate_chains_giga_graph_search(
                        None, dict(rop_regs), preserve_regs, False,
                        gadgets=pool, accept=accept, handle_hard=False)
                else:
                    seqs = [[]]
            except RopException:
                continue
            for seq in seqs:
                full = list(seq) + terminals
                if not full:
                    continue
                used_before = list(Builder.used_writable_ptrs)
                try:
                    table_ptr = self._alloc_table_ptr(len(full), d.dispatch_stride)
                    chain = self._build_jop_chain(full, d, r, table_ptr, dict(rop_regs))
                    if verify_fn(chain):
                        return chain
                except RopException:
                    pass
                # release the writable region a failed attempt reserved (a successful
                # attempt returns above and keeps its table reservation)
                Builder.used_writable_ptrs[:] = used_before
        raise RopException("JOP: couldn't build the requested primitive with the "
                           "available dispatcher/functional gadgets")

    def set_regs(self, preserve_regs=None, **registers):
        if not registers:
            from ..rop_chain import RopChain # pylint: disable=import-outside-toplevel
            return RopChain(self.project, self.chain_builder, badbytes=self.badbytes)
        return self._build_for(registers, preserve_regs=preserve_regs)

    def write_to_mem(self, addr, data, preserve_regs=None):
        """
        Ret-free word-sized memory write via a functional store gadget
        (`mov [addr_reg], data_reg ; jmp R`): set addr_reg=addr and data_reg=data via the
        search, then run the store as a (functional) table entry that returns to D.
        `data` is a single machine word (bytes or int).
        """
        arch_bytes = self.project.arch.bytes
        endian = "little" if self.project.arch.memory_endness == "Iend_LE" else "big"
        # the cet_forced route is taken before MemWriter's own sanity checks, so validate
        # here and fail with a clean RopException (not an AssertionError) on bad input.
        # preserve the address RopValue (and its PIE rebase relationship); cast first so a
        # bare symbolic AST is wrapped and the symbolic guard catches it too, not just a
        # pre-wrapped RopValue. Only the analysis-time absolute is used for the exec verify.
        addr_rv = addr if isinstance(addr, RopValue) else rop_utils.cast_rop_value(addr, self.project)
        if addr_rv.symbolic:
            raise RopException("cannot write to a symbolic address")
        if isinstance(data, bytes):
            if len(data) > arch_bytes:
                # multi-word writes (e.g. "/bin/sh"+argv) need chunked stores -- a future
                # increment; for now handle a single machine word and fail clearly otherwise
                raise RopException("JOP write_to_mem currently handles word-sized writes only")
            data = int.from_bytes(data.ljust(arch_bytes, b"\x00"), endian)
        elif not isinstance(data, int):
            raise RopException("data must be bytes or an int")
        addr_val = addr_rv.concreted

        for store in self._functional_stores():
            mw = store.mem_writes[0]
            addr_reg = self._single(mw.addr_dependencies)
            data_reg = self._single(mw.data_dependencies)
            if addr_reg is None or data_reg is None or addr_reg == data_reg:
                continue
            targets = {addr_reg: addr_rv, data_reg: data}
            verify = lambda chain, _a=addr_val, _d=data: self._verify_mem(chain, _a, _d)
            try:
                return self._build_for(targets, terminals=[store],
                                       preserve_regs=preserve_regs, verify_fn=verify)
            except RopException:
                continue
        raise RopException("JOP: couldn't write to memory with the available gadgets")

    @staticmethod
    def _single(dep_set):
        deps = set(dep_set)
        return next(iter(deps)) if len(deps) == 1 else None

    def _functional_stores(self):
        """functional gadgets that perform exactly one register-addressed memory write."""
        out = []
        for g in self.chain_builder.gadgets:
            if g.transit_type != "jmp_reg" or not g.has_endbr or g.has_conditional_branch:
                continue
            if len(g.mem_writes) != 1 or g.mem_reads or g.mem_changes:
                continue
            # word-sized stores only -- a sub-word store would leave the upper bytes of
            # the target word unconstrained, and the full-word verify would pass spuriously
            if g.mem_writes[0].data_size != self.project.arch.bits:
                continue
            out.append(g)
        return out

    def _verify_regs(self, chain, rop_regs):
        """exec() the JOP chain and confirm every concrete target register holds its value
        and control ended ret-free back at the dispatcher (C6)."""
        final = chain.exec()
        if final.solver.eval(final.regs.ip) != chain.dispatcher.addr:
            return False
        for reg, val in rop_regs.items():
            final_val = final.registers.load(reg)
            if val.symbolic:
                # a symbolic target asks for the register to remain attacker-controllable;
                # don't silently accept -- confirm the chain left it controllable (still
                # symbolic) rather than pinned to a concrete value by the gadgets
                if not final_val.symbolic:
                    return False
                continue
            if final.solver.eval(final_val) != val.concreted:
                return False
        return True

    def _verify_mem(self, chain, addr, data):
        """exec() the JOP chain and confirm `data` landed at `addr`, ret-free."""
        final = chain.exec()
        if final.solver.eval(final.regs.ip) != chain.dispatcher.addr:
            return False
        word = final.memory.load(addr, self.project.arch.bytes,
                                 endness=self.project.arch.memory_endness)
        return final.solver.eval(word) == data
