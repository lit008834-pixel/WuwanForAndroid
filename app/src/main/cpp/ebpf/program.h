// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <stddef.h>
#include <stdint.h>

// Stable Linux UAPI values, also usable with Android NDK 25's older headers.
#define WUWAN_TCX_EGRESS 47
#define WUWAN_LINK_CREATE 28
#define WUWAN_TCX_NEXT (-1)
#define INS(code_, dst_, src_, off_, imm_) \
    ((struct bpf_insn){.code=(code_), .dst_reg=(dst_), .src_reg=(src_), \
                      .off=(off_), .imm=(imm_)})
#define MOVI(d, i) INS(BPF_ALU64|BPF_MOV|BPF_K,d,0,0,i)
#define MOVR(d, s) INS(BPF_ALU64|BPF_MOV|BPF_X,d,s,0,0)
#define CALL(i) INS(BPF_JMP|BPF_CALL,0,0,0,i)
#define EXIT() INS(BPF_JMP|BPF_EXIT,0,0,0,0)

// No maps, pins, ELF loader, BTF or device-specific offsets. Linux validates
// __sk_buff context offsets at BPF_PROG_LOAD. Link FDs own attachment lifetime.
// Return NEXT for the proxy UID and non-IP traffic so Android's other filters
// still execute. Redirect IP packets to a layer-3 TUN (not an XDP program).
static size_t wuwan_program(struct bpf_insn *out, uint32_t uid, uint32_t tun) {
    struct bpf_insn ins[] = {
        MOVR(6, 1),
        CALL(BPF_FUNC_get_socket_uid),
        INS(BPF_JMP|BPF_JEQ|BPF_K,0,0,29,(int32_t)uid),
        // Android Fwmark.protectedFromVpn: preserve protected system DNS and
        // explicitly protected sockets, including calls made by netd for core.
        INS(BPF_LDX|BPF_MEM|BPF_W,2,6,offsetof(struct __sk_buff, mark),0),
        INS(BPF_ALU64|BPF_AND|BPF_K,2,0,0,0x20000),
        INS(BPF_JMP|BPF_JNE|BPF_K,2,0,26,0),
        INS(BPF_LDX|BPF_MEM|BPF_W,2,6,offsetof(struct __sk_buff, protocol),0),
        INS(BPF_JMP|BPF_JEQ|BPF_K,2,0,4,htons(ETH_P_IP)),
        INS(BPF_JMP|BPF_JNE|BPF_K,2,0,23,htons(ETH_P_IPV6)),
        MOVR(1, 6),
        MOVI(2, 24), // IPv6 destination first octet
        INS(BPF_JMP|BPF_JA,0,0,2,0),
        MOVR(1, 6),
        MOVI(2, 16), // IPv4 destination first octet
        MOVR(3, 10),
        INS(BPF_ALU64|BPF_ADD|BPF_K,3,0,0,-8),
        MOVI(4, 1),
        MOVI(5, 1), // BPF_HDR_START_NET
        CALL(BPF_FUNC_skb_load_bytes_relative),
        INS(BPF_JMP|BPF_JNE|BPF_K,0,0,12,0),
        INS(BPF_LDX|BPF_MEM|BPF_B,2,10,-8,0),
        INS(BPF_LDX|BPF_MEM|BPF_W,3,6,offsetof(struct __sk_buff, protocol),0),
        INS(BPF_JMP|BPF_JEQ|BPF_K,3,0,2,htons(ETH_P_IP)),
        INS(BPF_JMP|BPF_JEQ|BPF_K,2,0,8,255), // IPv6 multicast / ND
        INS(BPF_JMP|BPF_JEQ|BPF_K,2,0,7,254), // IPv6 link-local
        INS(BPF_JMP|BPF_JEQ|BPF_K,3,0,1,htons(ETH_P_IPV6)),
        INS(BPF_JMP|BPF_JGE|BPF_K,2,0,5,224), // IPv4 multicast / broadcast
        MOVI(1, (int32_t)tun),
        MOVI(2, 0),
        CALL(BPF_FUNC_redirect),
        EXIT(),
        MOVI(0, WUWAN_TCX_NEXT),
        MOVI(0, WUWAN_TCX_NEXT),
        EXIT(),
    };
    for (size_t i = 0; i < sizeof(ins)/sizeof(ins[0]); ++i) out[i] = ins[i];
    return sizeof(ins)/sizeof(ins[0]);
}
