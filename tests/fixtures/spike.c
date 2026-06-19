#include <stdint.h>
/* Raw gadget stubs, endbr-prefixed, each ending in an indirect transfer.
   rbx is the "dispatcher return register" R; rax is the data reg. */
__asm__(
".text\n"
".p2align 4\n"
".globl g_call_rax\n"           /* COP call-gadget + post-call continuation */
"g_call_rax:\n"
"    endbr64\n"
"    call *%rax\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_call_rax_bare\n"      /* COP call-gadget, no continuation */
"g_call_rax_bare:\n"
"    endbr64\n"
"    call *%rax\n"
".p2align 4\n"
".globl g_mov_rsp\n"            /* pivot: symbolic sp via reg + indirect jmp */
"g_mov_rsp:\n"
"    endbr64\n"
"    mov  %rax, %rsp\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_xchg_rsp\n"          /* pivot: xchg sp */
"g_xchg_rsp:\n"
"    endbr64\n"
"    xchg %rax, %rsp\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_add_rsp\n"           /* shift: constant sp delta + indirect jmp */
"g_add_rsp:\n"
"    endbr64\n"
"    add  $0x18, %rsp\n"
"    jmp  *%rbx\n"
".p2align 4\n"
".globl g_pop_rdi\n"           /* baseline functional gadget */
"g_pop_rdi:\n"
"    endbr64\n"
"    pop  %rdi\n"
"    jmp  *%rbx\n"
);
extern void g_call_rax(void), g_call_rax_bare(void), g_mov_rsp(void),
            g_xchg_rsp(void), g_add_rsp(void), g_pop_rdi(void);
void *keep[] = { g_call_rax, g_call_rax_bare, g_mov_rsp, g_xchg_rsp, g_add_rsp, g_pop_rdi };
int main(){ return (int)(uintptr_t)keep[0]; }
