# Capstone

ollvm 기본 최적화가 켜져있음

../bin/clang -O2 {C Code}.c -o {executable} -mllvm -bcf -mllvm -bcf_prob=10 -mllvm -bcf_loop=1