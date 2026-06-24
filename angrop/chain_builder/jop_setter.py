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

    def _build_for(self, reg_targets, terminals=(), preserve_regs=None, verify_fn=None,
                   terminal=False):
        """
        Core JOP builder shared by the data-plane primitives. For each (D, R) best-first:
        set `reg_targets` via the giga-graph search over the functional pool, append the
        `terminals` (gadgets that perform the primitive's operation -- e.g. a store or a
        syscall), build a JopChain, and accept it if `verify_fn(chain)` confirms the goal
        (default: the requested registers hold their values).

        `terminal=True` marks the last terminal as a stop-at-entry gadget (a syscall) that
        does not return to D: register targets are read right before it runs, and the
        terminal only needs to be a valid table entry (endbr), not is_functional(R, Rd).
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
        # terminal mode marks the LAST gadget as a stop-at-entry terminal; it must be one of
        # the `terminals`, never a pop from the search (which would be misclassified)
        if terminal and not terminals:
            raise RopException("terminal=True requires a terminal gadget")
        if verify_fn is None:
            verify_fn = lambda chain: self._verify_regs(chain, rop_regs)
        rs = self.chain_builder._reg_setter

        for d, r in self._candidate_dr():
            rd = d.dispatch_reg
            if target_regs & {r, rd}:
                continue
            # a normal terminal transfers via `jmp R` (functional) for this (D, R); a
            # `terminal` one (syscall) is only ever reached -- stop at its endbr entry --
            # so it just has to be a valid table entry, not return to D.
            if terminal:
                if not all(t.has_endbr for t in terminals):
                    continue
            elif not all(t.is_functional(r, rd) for t in terminals):
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
                    chain = self._build_jop_chain(full, d, r, table_ptr, dict(rop_regs),
                                                  terminal=terminal)
                    if verify_fn(chain):
                        return chain
                except RopException:
                    pass
                # release the writable region a failed attempt reserved (a successful
                # attempt returns above and keeps its table reservation)
                Builder.used_writable_ptrs[:] = used_before
        raise RopException("JOP: couldn't build the requested primitive with the "
                           "available dispatcher/functional gadgets")

    def _build_multiop(self, ops_spec, preserve_regs=None, verify_fn=None, terminal_last=False):
        """
        Build ONE JOP chain that performs a SEQUENCE of operations. `ops_spec` is an ordered
        list of (reg_targets, op_gadget): for each op, set reg_targets via the search then run
        op_gadget. All ops share one (D, R)/dispatch table, and each op's registers are
        constrained at ITS op gadget (so a register reused across ops -- e.g. the store
        address reg -- can hold a different value per op). `terminal_last` marks the final
        op_gadget as a stop-at-entry terminal (a syscall). (D, R) is the outer loop: if any
        op's search fails for a candidate (D, R), fall through to the next.
        """
        preserve_regs = set(preserve_regs) if preserve_regs else set()
        if verify_fn is None:
            raise RopException("multi-op build requires a verify function")
        rs = self.chain_builder._reg_setter
        try:
            specs = [({rr: rop_utils.cast_rop_value(v, self.project) for rr, v in rt.items()}, g)
                     for rt, g in ops_spec]
        except ValueError as e:
            raise RopException(str(e)) from e

        for d, r in self._candidate_dr():
            rd = d.dispatch_reg
            # every op must transfer correctly for this (D, R): a store returns to D
            # (is_functional); a terminal-last op only needs to be a valid table entry (endbr).
            # No op may target the dispatch machinery regs (R/Rd).
            ok = True
            for i, (rt, g) in enumerate(specs):
                if set(rt) & {r, rd}:
                    ok = False
                    break
                if terminal_last and i == len(specs) - 1:
                    if not g.has_endbr:
                        ok = False
                        break
                elif not g.is_functional(r, rd):
                    ok = False
                    break
            if not ok:
                continue

            used_before = list(Builder.used_writable_ptrs)
            try:
                full, ops = [], []
                for rt, g in specs:
                    pool = self._functional_pool(r, rd, set(rt))
                    if not pool:
                        raise RopException("no functional pool for this op")
                    accept = lambda gg, _r=r, _rd=rd: gg.is_functional(_r, _rd)
                    seqs = rs.find_candidate_chains_giga_graph_search(
                        None, dict(rt), preserve_regs, False,
                        gadgets=pool, accept=accept, handle_hard=False)
                    seq = next(iter(seqs), None)
                    if seq is None:
                        raise RopException("op search produced no sequence")
                    full.extend(seq)
                    ops.append((len(full), rt))   # index of the op gadget appended next
                    full.append(g)
                table_ptr = self._alloc_table_ptr(len(full), d.dispatch_stride)
                chain = self._build_jop_chain(full, d, r, table_ptr, ops=ops,
                                              terminal=terminal_last)
                if verify_fn(chain):
                    return chain
            except RopException:
                pass
            Builder.used_writable_ptrs[:] = used_before
        raise RopException("JOP: couldn't build the requested multi-operation primitive")

    def set_regs(self, preserve_regs=None, **registers):
        if not registers:
            from ..rop_chain import RopChain # pylint: disable=import-outside-toplevel
            return RopChain(self.project, self.chain_builder, badbytes=self.badbytes)
        return self._build_for(registers, preserve_regs=preserve_regs)

    def write_to_mem(self, addr, data, preserve_regs=None, fill_byte=b"\xff"):
        """
        Ret-free memory write via a functional store gadget (`mov [addr_reg], data_reg; jmp R`):
        set addr_reg/data_reg via the search and run the store as a table entry returning to D.
        `data` longer than one machine word is chunked into consecutive word-stores composed
        into ONE chain (the multi-operation builder), so each word's address/data are
        constrained at its own store (the address register is reused across stores). A
        sub-word tail is padded with `fill_byte` (default 0xff, matching MemWriter -- 0x00 is
        a common badbyte).
        """
        arch_bytes = self.project.arch.bytes
        endian = "little" if self.project.arch.memory_endness == "Iend_LE" else "big"
        # the cet_forced route is taken before MemWriter's own sanity checks, so validate
        # here and fail with a clean RopException (not an AssertionError/ValueError) on bad
        # input, mirroring the legacy boundary checks (fill_byte shape + badbyte).
        if not (isinstance(fill_byte, bytes) and len(fill_byte) == 1):
            raise RopException("fill_byte is not a one byte string, aborting")
        if ord(fill_byte) in self.badbytes:
            raise RopException("fill_byte is a bad byte!")
        # preserve the address RopValue (and its PIE rebase relationship); cast first so a
        # bare symbolic AST is wrapped and the symbolic guard catches it too, not just a
        # pre-wrapped RopValue. Only the analysis-time absolute is used for the exec verify.
        try:
            addr_rv = addr if isinstance(addr, RopValue) else rop_utils.cast_rop_value(addr, self.project)
        except ValueError as e:
            raise RopException(str(e)) from e
        if addr_rv.symbolic:
            raise RopException("cannot write to a symbolic address")
        # chunk data into machine words (sub-word tail padded with fill_byte)
        if isinstance(data, bytes):
            words = [int.from_bytes(data[i:i + arch_bytes].ljust(arch_bytes, fill_byte), endian)
                     for i in range(0, len(data), arch_bytes)]
        elif isinstance(data, int):
            words = [data]
        else:
            raise RopException("data must be bytes or an int")
        if not words:
            raise RopException("JOP write_to_mem: no data to write")
        addr_val = addr_rv.concreted

        for store in self._functional_stores():
            mw = store.mem_writes[0]
            addr_reg = self._single(mw.addr_dependencies)
            data_reg = self._single(mw.data_dependencies)
            if addr_reg is None or addr_reg == data_reg or data_reg is None:
                continue
            off = mw.addr_offset or 0
            # one op per word: word_i lands at addr + i*arch_bytes. Fold the store
            # displacement into the addr-register target so the write hits the right slot
            # (PIE rebase preserved via RopValue arithmetic); a wrong offset only fails the
            # verify and drops the candidate, never a bad chain.
            ops_spec = [({addr_reg: addr_rv + (i * arch_bytes - off), data_reg: w}, store)
                        for i, w in enumerate(words)]
            writes = [(addr_val + i * arch_bytes, w) for i, w in enumerate(words)]
            try:
                if len(words) == 1:
                    verify = lambda c, _a=writes[0][0], _d=writes[0][1]: self._verify_mem(c, _a, _d)
                    return self._build_for(ops_spec[0][0], terminals=[store],
                                           preserve_regs=preserve_regs, verify_fn=verify)
                verify = lambda c, _w=list(writes): self._verify_multimem(c, _w)
                return self._build_multiop(ops_spec, preserve_regs=preserve_regs, verify_fn=verify)
            except RopException:
                continue
        raise RopException("JOP: couldn't write to memory with the available gadgets")

    def _syscall_gadgets(self):
        """endbr syscall gadgets usable as a terminal JOP table entry (the dispatcher can
        only branch to an endbr address). Sourced from the syscall pool, not the general
        gadget pool (the analyzer keeps SyscallGadgets separately)."""
        return [g for g in (self.chain_builder.syscall_gadgets or []) if g.has_endbr]

    def do_syscall(self, syscall_num, args, needs_return=False, preserve_regs=None):
        """
        Ret-free syscall (C9). Set the syscall-number register + the argument registers via
        the search, then dispatch to a syscall gadget as a TERMINAL table entry: stepping
        stops at its endbr entry, with the registers set right before `syscall` runs (the
        syscall clobbers rax, so they can't be checked afterwards). `args` are register
        values (immediates/addresses); staging argument data into memory is a separate
        primitive. `needs_return` is accepted for signature parity but a JOP syscall does
        not model post-syscall continuation (execve replaces the process anyway).
        """
        import angr # pylint: disable=import-outside-toplevel
        if needs_return:
            # continuation after the syscall would need a functional (returns-to-D) syscall
            # gadget plus mid-chain reg constraints (the syscall clobbers rax) -- a later
            # increment. The terminal model stops at the syscall, so only needs_return=False.
            raise RopException("JOP do_syscall: needs_return=True is not yet supported "
                               "(continuation after a ret-free syscall); pass needs_return=False")
        if not isinstance(args, (list, tuple)):
            raise RopException("JOP do_syscall: args must be a list or tuple of register values")
        cc = angr.SYSCALL_CC[self.project.arch.name]["default"](self.project.arch)
        if len(args) > len(cc.ARG_REGS):
            raise RopException("JOP do_syscall: stack syscall arguments are not supported")
        sysnum_reg = self.project.arch.register_names[self.project.arch.syscall_num_offset]
        reg_targets = {sysnum_reg: syscall_num}
        for arg, reg in zip(args, cc.ARG_REGS):
            reg_targets[reg] = arg

        gadgets = self._syscall_gadgets()
        if not gadgets:
            raise RopException("target has no endbr syscall gadget for a ret-free syscall")
        target_regs = set(reg_targets)
        for sc in gadgets:
            # the chain stages the arg/sysnum registers BEFORE dispatching to `sc`, and the
            # verify stops at sc's entry. If sc's own prologue (its instructions between the
            # entry and `syscall`) writes one of those target registers, the staged value
            # would be clobbered before the syscall runs -- the chain would verify-at-entry
            # but execute the syscall with the wrong register. Skip such a gadget.
            # (concrete_regs ⊆ changed_regs in practice, but union both for parity with the
            # legacy clobber check in case a write escapes changed_regs.)
            prologue = getattr(sc, "prologue", None)
            if prologue is not None and \
                    (set(prologue.changed_regs) | set(prologue.concrete_regs)) & target_regs:
                continue
            try:
                return self._build_for(reg_targets, terminals=[sc],
                                       preserve_regs=preserve_regs, terminal=True)
            except RopException:
                continue
        raise RopException("JOP: couldn't invoke the syscall with the available gadgets")

    def execve(self, path=None, path_addr=None):
        """
        Ret-free execve (C9). If `path_addr` is given the path string must already be in
        memory there, and only the execve syscall is built. Otherwise the path string is
        staged into a fresh writable buffer AND the execve syscall is invoked -- both in ONE
        chain via the multi-operation builder ([string-word stores] + [terminal syscall]).
        """
        arch_bytes = self.project.arch.bytes
        endian = "little" if self.project.arch.memory_endness == "Iend_LE" else "big"
        ptr0 = rop_utils.cast_rop_value(0, self.project)

        if path_addr is not None:
            # path already in memory: just the syscall (reject a symbolic pointer cleanly,
            # consistent with write_to_mem)
            path_rv = rop_utils.cast_rop_value(path_addr, self.project)
            if path_rv.symbolic:
                raise RopException("JOP execve requires a concrete path_addr")
            return self.do_syscall(self.arch.execve_num, [path_rv, ptr0, ptr0],
                                   needs_return=False)

        # stage the path string + execve in one chain
        if path is None:
            path = b"/bin/sh\x00"
        if not isinstance(path, bytes):
            raise RopException("execve path must be bytes")
        if not path.endswith(b"\x00"):
            path += b"\x00"
        words = [int.from_bytes(path[i:i + arch_bytes].ljust(arch_bytes, b"\x00"), endian)
                 for i in range(0, len(path), arch_bytes)]

        syscalls = self._syscall_gadgets()
        if not syscalls:
            raise RopException("target has no endbr syscall gadget for a ret-free execve")
        sysnum_reg = self.project.arch.register_names[self.project.arch.syscall_num_offset]
        import angr # pylint: disable=import-outside-toplevel
        arg_regs = angr.SYSCALL_CC[self.project.arch.name]["default"](self.project.arch).ARG_REGS

        for store in self._functional_stores():
            mw = store.mem_writes[0]
            addr_reg = self._single(mw.addr_dependencies)
            data_reg = self._single(mw.data_dependencies)
            if addr_reg is None or data_reg is None or addr_reg == data_reg:
                continue
            off = mw.addr_offset or 0
            for sc in syscalls:
                used_before = list(Builder.used_writable_ptrs)
                try:
                    # _get_ptr_to_writable raises (not None) if the region is exhausted
                    buf = self._get_ptr_to_writable(len(words) * arch_bytes + arch_bytes)
                    buf_rv = rop_utils.cast_rop_value(buf, self.project)
                    # store ops write the path words into the buffer; the terminal syscall op
                    # then runs execve(buf, 0, 0)
                    sys_targets = {sysnum_reg: self.arch.execve_num,
                                   arg_regs[0]: buf_rv, arg_regs[1]: ptr0, arg_regs[2]: ptr0}
                    # the syscall prologue must not clobber a target reg (verify stops at the
                    # syscall entry, like do_syscall)
                    prologue = getattr(sc, "prologue", None)
                    if prologue is not None and \
                            (set(prologue.changed_regs) | set(prologue.concrete_regs)) & set(sys_targets):
                        raise RopException("syscall prologue clobbers a target register")
                    ops_spec = [({addr_reg: buf_rv + (i * arch_bytes - off), data_reg: w}, store)
                                for i, w in enumerate(words)]
                    ops_spec.append((sys_targets, sc))
                    writes = [(buf_rv.concreted + i * arch_bytes, w) for i, w in enumerate(words)]
                    reg_expect = {sysnum_reg: self.arch.execve_num,
                                  arg_regs[0]: buf_rv.concreted, arg_regs[1]: 0, arg_regs[2]: 0}
                    verify = lambda c, _w=writes, _e=dict(reg_expect): self._verify_execve(c, _w, _e)
                    return self._build_multiop(ops_spec, verify_fn=verify, terminal_last=True)
                except RopException:
                    Builder.used_writable_ptrs[:] = used_before
                    continue
        raise RopException("JOP: couldn't build a ret-free execve with the available gadgets")

    def _call_gadgets(self):
        """endbr CALL gadgets (`... ; call reg`) usable as a terminal COP table entry. The
        precise signal is the terminating block's Ijk_Call jumpkind: a `push <const>; jmp reg`
        has the SAME stack_change/mem_write but does NOT push the shadow stack, so the callee's
        `ret` would fault under CET. Verify-at-entry can't observe this (we stop before the
        call), so detection must be exact -- the stack/mem-write heuristic alone is unsafe."""
        out = []
        for g in self.chain_builder.gadgets:
            if g.transit_type != "jmp_reg" or not g.has_endbr or g.has_conditional_branch:
                continue
            if not getattr(g, "pc_reg", None):
                continue
            try:
                last_blk = g.bbl_addrs[-1] if getattr(g, "bbl_addrs", None) else g.addr
                if self.project.factory.block(last_blk).vex.jumpkind != "Ijk_Call":
                    continue
            except Exception: # pylint: disable=broad-except
                continue
            out.append(g)
        return out

    def _resolve_func_addr(self, address):
        """resolve a function symbol / PLT name / address to a (rebase-aware) RopValue."""
        if isinstance(address, RopValue):
            return address
        if isinstance(address, str):
            main = self.project.loader.main_object
            if getattr(main, "plt", None) and address in main.plt:
                address = main.plt[address]
            else:
                sym = main.get_symbol(address)
                if sym is None:
                    raise RopException(f"symbol {address!r} not found in the binary")
                address = sym.rebased_addr
        if not isinstance(address, int):
            raise RopException("func_call address must be an int, a symbol name, or a RopValue")
        return rop_utils.cast_rop_value(address, self.project)

    def func_call(self, address, args, needs_return=False, preserve_regs=None):
        """
        Ret-free function call (COP, C10). A `call reg` gadget pushes the return address to the
        shadow stack and the callee's matching `ret` is balanced (no CET fault); the post-call
        continuation goes ret-free via the gadget's trailing `jmp R`. The build stops at the
        call gadget's entry with the function address (in the call-target register) and the
        argument registers set -- the call fires at exploit time. `needs_return=True`
        (continuing the chain *after* the call) needs the hook-and-step + callee-saved R/Rd
        and is not supported here; post-call behaviour for a returning function is undefined.
        """
        import angr # pylint: disable=import-outside-toplevel
        if needs_return:
            raise RopException("JOP func_call: needs_return=True is not yet supported "
                               "(continuation after a ret-free call); pass needs_return=False")
        func_rv = self._resolve_func_addr(address)
        args = list(args)
        cc = angr.default_cc(self.project.arch.name,
                             platform=self.project.simos.name if self.project.simos else None
                             )(self.project.arch)
        if len(args) > len(cc.ARG_REGS):
            raise RopException("JOP func_call: stack call arguments are not supported")
        gadgets = self._call_gadgets()
        if not gadgets:
            raise RopException("target has no endbr call gadget for a ret-free COP call")
        arg_map = dict(zip(cc.ARG_REGS, args))
        for cg in gadgets:
            pc_reg = cg.pc_reg
            if pc_reg in arg_map: # the call-target register can't also carry an argument
                continue
            reg_targets = {pc_reg: func_rv}
            reg_targets.update(arg_map)
            # verify stops at the call entry; gadget analysis stops at the call, so the call
            # gadget's own changed_regs ARE its entry->call effect set. If it writes a target
            # register before the call (e.g. `mov rdi, rbx; call rax`), verify-at-entry would
            # pass but the call would fire with the wrong value -- skip such a gadget. Union
            # concrete_regs for parity with the syscall prologue guard (concrete_regs is a
            # subset, but keep the check identical).
            if (set(cg.changed_regs) | set(cg.concrete_regs)) & set(reg_targets):
                continue
            try:
                return self._build_for(reg_targets, terminals=[cg],
                                       preserve_regs=preserve_regs, terminal=True)
            except RopException:
                continue
        raise RopException("JOP: couldn't invoke the function with the available call gadgets")

    def _verify_execve(self, chain, writes, reg_expect):
        """exec() the terminal chain (stops at the syscall entry) and confirm the path string
        landed in the buffer and the syscall number + argument registers are set right before
        the syscall runs."""
        final = chain.exec()
        if final.solver.eval(final.regs.ip) != chain.table_addrs[-1]:
            return False
        if not self._confirm_writes(final, writes):
            return False
        for reg, val in reg_expect.items():
            if final.solver.eval(final.registers.load(reg)) != val:
                return False
        return True

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
        and control ended where expected -- ret-free back at the dispatcher, or (for a
        terminal syscall chain) at the syscall gadget's entry, right before it runs (C6)."""
        final = chain.exec()
        expected_ip = chain.table_addrs[-1] if chain.terminal else chain.dispatcher.addr
        if final.solver.eval(final.regs.ip) != expected_ip:
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

    @staticmethod
    def _written_addrs(state):
        """concrete base addresses of every memory-write action during the chain's exec."""
        out = set()
        for a in state.history.actions.hardcopy:
            if a.type == "mem" and a.action == "write":
                try:
                    out.add(state.solver.eval(a.addr.ast))
                except Exception: # pylint: disable=broad-except
                    pass
        return out

    def _confirm_writes(self, final, writes):
        """confirm every (addr, data) was actually written at `addr`. Checking the slot value
        alone is not enough -- a zero data word at a wrong (zeroed) address reads back as
        correct -- so also require that a store action landed at each address."""
        written = self._written_addrs(final)
        for addr, data in writes:
            if addr not in written:
                return False
            word = final.memory.load(addr, self.project.arch.bytes,
                                     endness=self.project.arch.memory_endness)
            if final.solver.eval(word) != data:
                return False
        return True

    def _verify_mem(self, chain, addr, data):
        """exec() the JOP chain and confirm `data` landed at `addr`, ret-free."""
        final = chain.exec()
        if final.solver.eval(final.regs.ip) != chain.dispatcher.addr:
            return False
        return self._confirm_writes(final, [(addr, data)])

    def _verify_multimem(self, chain, writes):
        """exec() the JOP chain once and confirm every (addr, data) word landed, ret-free."""
        final = chain.exec()
        if final.solver.eval(final.regs.ip) != chain.dispatcher.addr:
            return False
        return self._confirm_writes(final, writes)
