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
".globl g_clobber\n"            /* NOT a dispatcher: also clobbers rcx (changed_regs not subset {rbp}) */
"g_clobber:\n"
"    endbr64\n"
"    add  $8, %rbp\n"
"    mov  $0, %rcx\n"
"    jmp  *-8(%rbp)\n"
);
extern void g_disp(void), g_disp_c0(void), g_disp_sub(void), g_pop_rdi(void),
            g_pop_rdi_ret(void), g_pop_rsi(void), g_pop_rdx(void), g_store(void),
            g_store_off(void), g_clobber(void);
void *keep[] = { g_disp, g_disp_c0, g_disp_sub, g_pop_rdi, g_pop_rdi_ret,
                 g_pop_rsi, g_pop_rdx, g_store, g_store_off, g_clobber };
int main(){ return (int)(uintptr_t)keep[0]; }
