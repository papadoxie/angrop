#include <unistd.h>
// A few functions so the binary has endbr-prefixed entries and some gadgets.
__attribute__((noinline)) long add2(long a, long b){ return a+b; }
__attribute__((noinline)) long ident(long a){ return a; }
int main(int argc, char**argv){
    long x = add2(argc, 3);
    x = ident(x);
    write(1, argv[0], (size_t)(x & 7));
    return 0;
}
