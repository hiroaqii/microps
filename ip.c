#include "ip.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "net.h"
#include "util.h"

struct ip_hdr {
    uint8_t vhl;     // バージョン(4bit)とIPヘッダ長(4bit)
    uint8_t tos;     // サービス種別
    uint16_t total;  // データグラム全体の長さ
    uint16_t id;     // 識別子
    uint16_t offset;  // フラグ(3bit)とフラグメントオフセット(13bit)
    uint8_t ttl;      // 生存時間（TTL: Time To Live）
    uint8_t protocol;  // プロトコル番号
    uint16_t sum;      // チェックサム
    ip_addr_t src;     // 送信元IPアドレス
    ip_addr_t dst;     // 宛先IPアドレス
    uint8_t options[];
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

// IPアドレスを文字列からネットワークバイトオーダーのバイナリ値に変換
int ip_addr_pton(const char *p, ip_addr_t *n) {
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

// IPアドレスをネットワークバイトオーダーのバイナリ値から文字列に変換
char *ip_addr_ntop(ip_addr_t n, char *p, size_t size) {
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

static void ip_dump(const uint8_t *data, size_t len) {
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    hlen = hl << 2;
    fprintf(stderr, "        vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v,
            hl, hlen);
    fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total);
    fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset,
            (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "        ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->protocol);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "        src: %s\n",
            ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n",
            ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

static void ip_input(const uint8_t *data, size_t len, struct net_device *dev) {
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;

    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }
    hdr = (struct ip_hdr *)data;

    // IP_VERSION_IPV4 と一致しない場合はエラーメッセージを出力して中断
    v = hdr->vhl >> 4;
    if (IP_VERSION_IPV4 != v) {
        errorf("ip version error: v=%u", v);
        return;
    }

    // 入力データの長さ（len）がヘッダ長より小さい場合はエラーメッセージを出力して中断
    hlen = (hdr->vhl & 0x0f) << 2;
    if (len < hlen) {
        errorf("header length error: len=%zu < hlen=%u", len, hlen);
        return;
    }

    // 入力データの長さ（len）がトータル長より小さい場合はエラーメッセージを出力して中断
    total = ntoh16(hdr->total);
    if (len < total) {
        errorf("total length error: len=%zu < total=%u", len, total);
        return;
    }

    // cksum16() での検証に失敗した場合はエラーメッセージを出力して中断
    if (cksum16((uint16_t *)hdr, hlen, 0) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum),
               ntoh16(cksum16((uint16_t *)hdr, hlen, -hdr->sum)));
        return;
    }

    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff) {
        errorf("fragments does not support");
        return;
    }
    debugf("dev=%s, protocol=%u, total=%u", dev->name, hdr->protocol, total);
    ip_dump(data, total);
}

// プロトコルスタックにIPの入力関数を登録
int ip_init(void) {
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}