// SPDX-License-Identifier: GPL-3.0-or-later
// Userspace interpreter for this program's small instruction subset. Tests
// forwarding semantics, jump targets, UID exemption and network control bypass.
#include "program.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int execute(unsigned uid, unsigned protocol, unsigned destination, int load_error, unsigned mark) {
    struct bpf_insn program[64];
    size_t count = wuwan_program(program, 10000, 42);
    struct __sk_buff skb = {.protocol = htons(protocol), .mark = mark};
    uint8_t stack[64] = {0};
    uint64_t r[11] = {0};
    r[1] = (uintptr_t)&skb;
    r[10] = (uintptr_t)(stack+sizeof(stack));
    for (size_t pc = 0, steps = 0; pc < count && steps++ < 100; ++pc) {
        struct bpf_insn i = program[pc];
        switch (i.code) {
        case BPF_ALU64|BPF_MOV|BPF_K: r[i.dst_reg] = (int64_t)i.imm; break;
        case BPF_ALU64|BPF_MOV|BPF_X: r[i.dst_reg] = r[i.src_reg]; break;
        case BPF_ALU64|BPF_AND|BPF_K: r[i.dst_reg] &= i.imm; break;
        case BPF_ALU64|BPF_ADD|BPF_K: r[i.dst_reg] += i.imm; break;
        case BPF_LDX|BPF_MEM|BPF_W: {
            uint32_t word; memcpy(&word, (void *)(r[i.src_reg]+i.off), 4);
            r[i.dst_reg] = word; break;
        }
        case BPF_LDX|BPF_MEM|BPF_B:
            r[i.dst_reg] = *(uint8_t *)(r[i.src_reg]+i.off); break;
        case BPF_JMP|BPF_CALL:
            if (i.imm == BPF_FUNC_get_socket_uid) r[0] = uid;
            else if (i.imm == BPF_FUNC_skb_load_bytes_relative) {
                assert(r[2] == (protocol == ETH_P_IP ? 16u : 24u));
                assert(r[4] == 1 && r[5] == 1);
                *(uint8_t *)r[3] = destination;
                r[0] = load_error ? -1 : 0;
            } else if (i.imm == BPF_FUNC_redirect) {
                assert(r[1] == 42 && r[2] == 0); r[0] = 7;
            } else assert(0);
            for (int j = 1; j <= 5; ++j) r[j] = 0; // helper clobbers argument registers
            break;
        case BPF_JMP|BPF_JEQ|BPF_K:
            if (r[i.dst_reg] == (uint64_t)(int64_t)i.imm) pc += i.off;
            break;
        case BPF_JMP|BPF_JNE|BPF_K:
            if (r[i.dst_reg] != (uint64_t)(int64_t)i.imm) pc += i.off;
            break;
        case BPF_JMP|BPF_JGE|BPF_K:
            if (r[i.dst_reg] >= (uint64_t)(int64_t)i.imm) pc += i.off;
            break;
        case BPF_JMP|BPF_JA: pc += i.off; break;
        case BPF_JMP|BPF_EXIT: return (int)r[0];
        default: assert(0);
        }
    }
    assert(!"program failed to terminate");
    return 99;
}

static int run(unsigned uid, unsigned protocol, unsigned destination, int load_error) {
    return execute(uid, protocol, destination, load_error, 0);
}

int main(void) {
    assert(execute(1051, ETH_P_IP, 8, 0, 0x20000) == -1);
    assert(run(10001, ETH_P_IP, 8, 0) == 7);
    assert(run(10001, ETH_P_IPV6, 0x20, 0) == 7);
    assert(run(10001, ETH_P_IPV6, 0xfd, 0) == 7);
    assert(run(10000, ETH_P_IP, 8, 0) == -1);
    assert(run(10000, ETH_P_IPV6, 0x20, 0) == -1);
    assert(run(0, ETH_P_IP, 8, 0) == 7);
    assert(run(10001, ETH_P_ARP, 0, 0) == -1);
    assert(run(10001, ETH_P_IPV6, 0xff, 0) == -1);
    assert(run(10001, ETH_P_IPV6, 0xfe, 0) == -1);
    assert(run(10001, ETH_P_IP, 224, 0) == -1);
    assert(run(10001, ETH_P_IP, 255, 0) == -1);
    assert(run(10001, ETH_P_IP, 8, 1) == -1);
    puts("13 eBPF routing cases passed");
}
