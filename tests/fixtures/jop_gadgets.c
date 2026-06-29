#include <stdint.h>
/* Canonical JOP gadget shapes, endbr-prefixed, for Phase 1 classification tests.
   rbx is the return register R; rbp is the dispatch register Rd. Built -no-pie so
   the symbols sit at fixed addresses (the tests discover them by name regardless). */
__asm__(
".text\n"
".p2align 4\n"
".globl g_disp\n"               /* dispatcher: add rbp,8; jmp [rbp-8]  => Rd=rbp, s=8, c=8, delta=0 */
"g_disp:\n"
"    endbr64\n"
"    add  $8, %rbp\n"
"    jmp  *-8(%rbp)\n"
".p2align 4\n"
".globl g_disp_c0\n"            /* dispatcher c=0: add rbp,8; jmp [rbp]   => Rd=rbp, s=8, c=0, delta=8 */
"g_disp_c0:\n"
"    endbr64\n"
"    add  $8, %rbp\n"
"    jmp  *(%rbp)\n"
".p2align 4\n"
".globl g_disp_sub\n"           /* negative stride: sub rbp,8; jmp [rbp+8] => s=-8, c=-8, delta=0 */
"g_disp_sub:\n"
"    endbr64\n"
"    sub  $8, %rbp\n"
"    jmp  *8(%rbp)\n"
".p2align 4\n"
".globl g_pop_rdi\n"            /* functional: pop rdi; jmp rbx */
"g_pop_rdi:\n"
"    endbr64\n"
"    pop  %rdi\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_pop_rdi_ret\n"        /* ret-twin of g_pop_rdi (same body, ret transit) for C4 */
"g_pop_rdi_ret:\n"
"    endbr64\n"
"    pop  %rdi\n"
"    ret\n"
".p2align 4\n"
".globl g_pop_rsi\n"            /* functional: pop rsi; jmp rbx */
"g_pop_rsi:\n"
"    endbr64\n"
"    pop  %rsi\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_pop_rdx\n"            /* functional: pop rdx; jmp rbx */
"g_pop_rdx:\n"
"    endbr64\n"
"    pop  %rdx\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_pop_rax\n"            /* functional: pop rax; jmp rbx (syscall number reg) */
"g_pop_rax:\n"
"    endbr64\n"
"    pop  %rax\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_store\n"             /* functional store: mov [rdi], rsi; jmp rbx */
"g_store:\n"
"    endbr64\n"
"    mov  %rsi, (%rdi)\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_store_off\n"         /* offset store: mov [rdi+0x10], rsi; jmp rbx (addr_offset=0x10) */
"g_store_off:\n"
"    endbr64\n"
"    mov  %rsi, 0x10(%rdi)\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_syscall\n"           /* syscall table entry: endbr64; syscall; jmp rbx (terminal-stop at entry) */
"g_syscall:\n"
"    endbr64\n"
"    syscall\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_syscall_xor\n"       /* syscall with a prologue that writes rsi (endbr; xor esi,esi; syscall) */
"g_syscall_xor:\n"
"    endbr64\n"
"    xor  %esi, %esi\n"
"    syscall\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_call_rax\n"          /* COP call gadget: endbr64; call rax; jmp rbx (Ijk_Call) */
"g_call_rax:\n"
"    endbr64\n"
"    call *%rax\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_push_jmp\n"          /* call IMPOSTOR: endbr64; push $imm; jmp rax (same stack effect, Ijk_Boring) */
"g_push_jmp:\n"
"    endbr64\n"
"    push $0x401100\n"
"    jmp  *%rax\n"
".p2align 4\n"
".globl g_call_clobber\n"      /* call gadget that writes rdi before the call (entry->call clobbers rdi) */
"g_call_clobber:\n"
"    endbr64\n"
"    mov  %rbx, %rdi\n"
"    call *%rax\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_shift\n"             /* JOP shift: add rsp,0x18; jmp rbx (functional sp advance, C11) */
"g_shift:\n"
"    endbr64\n"
"    add  $0x18, %rsp\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_pivot\n"             /* JOP pivot: mov rax,rsp (rsp=rax); jmp rbx (PivotGadget, C11) */
"g_pivot:\n"
"    endbr64\n"
"    mov  %rax, %rsp\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_pivot_mem\n"         /* memory-INDIRECT pivot (rsp=[rax]): empty sp_reg_controllers -> excluded */
"g_pivot_mem:\n"
"    endbr64\n"
"    mov  (%rax), %rsp\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_clobber\n"            /* NOT a dispatcher: also clobbers rcx (changed_regs not subset {rbp}) */
"g_clobber:\n"
"    endbr64\n"
"    add  $8, %rbp\n"
"    mov  $0, %rcx\n"
"    jmp  *-8(%rbp)\n"
);
extern void g_disp(void), g_disp_c0(void), g_disp_sub(void), g_pop_rdi(void),
            g_pop_rdi_ret(void), g_pop_rsi(void), g_pop_rdx(void), g_pop_rax(void),
            g_store(void), g_store_off(void), g_syscall(void), g_syscall_xor(void),
            g_call_rax(void), g_push_jmp(void), g_call_clobber(void),
            g_shift(void), g_pivot(void), g_pivot_mem(void), g_clobber(void);
void *keep[] = { g_disp, g_disp_c0, g_disp_sub, g_pop_rdi, g_pop_rdi_ret,
                 g_pop_rsi, g_pop_rdx, g_pop_rax, g_store, g_store_off, g_syscall,
                 g_syscall_xor, g_call_rax, g_push_jmp, g_call_clobber,
                 g_shift, g_pivot, g_pivot_mem, g_clobber };
int main(){ return (int)(uintptr_t)keep[0]; }
