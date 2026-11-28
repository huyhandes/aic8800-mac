/* AIC8800 USB RX parsers: bulk-IN demux, 802.11 data to Ethernet (plain and A-MSDU), MSG URB dispatch */
#include "aic8800_framing.h"
#include "aic8800_lmac.h"
#include <assert.h>
#include <stdio.h>

static int n_data, n_cfg, n_eth;
static size_t last_len;
static uint8_t last_cfg_type, last_eth[64];

static void on_data(const uint8_t *c, size_t len, void *ctx) { (void)c; (void)ctx; n_data++; last_len = len; }
static void on_cfg(uint8_t t, const uint8_t *p, size_t len, void *ctx) { (void)p; (void)ctx; n_cfg++; last_cfg_type = t; last_len = len; }
static void on_eth(const uint8_t *f, size_t len, const aic_rx_frame_meta_t *m, void *ctx) {
    (void)m; (void)ctx; n_eth++; last_len = len; memcpy(last_eth, f, len < sizeof(last_eth) ? len : sizeof(last_eth));
}

/* hw_rxhdr (60 bytes) + 802.11 header; returns the offset just past the MAC header */
static size_t chunk_hdr(uint8_t *c, uint8_t fc0, uint8_t fc1, uint8_t decr) {
    memset(c, 0, 256);
    aic_hw_rxhdr_t h;
    memset(&h, 0, sizeof(h));
    h.hwvect.decr_status = decr;
    memcpy(c, &h, sizeof(h));
    uint8_t *m = &c[AIC_RX_HWHDR_LEN];
    m[0] = fc0; m[1] = fc1;
    memset(&m[4], 0xA1, 6); memset(&m[10], 0xB2, 6); memset(&m[16], 0xC3, 6);
    return AIC_RX_HWHDR_LEN + 24U;
}

int main(void) {
    /* demux: one data packet (pkt_len + 60-byte hw header), then a CMD_RSP padded to 4 */
    uint8_t buf[256] = {0};
    buf[0] = 30; buf[2] = AIC_USB_TYPE_DATA;
    size_t o = 30U + AIC_RX_HWHDR_LEN;
    buf[o] = 5; buf[o + 2] = AIC_USB_TYPE_CFG_CMD_RSP;
    assert(aic_rx_demux_usb_aggr(buf, o + 4U + 8U, on_data, on_cfg, NULL) == 2);
    assert(n_data == 1 && n_cfg == 1 && last_cfg_type == 0x11 && last_len == 5U);
    /* the last CFG packet may come without its padding */
    assert(aic_rx_demux_usb_aggr(buf, o + 4U + 5U, NULL, NULL, NULL) == 2);
    /* truncated header, length past the buffer, zero-length data: rejected */
    assert(aic_rx_demux_usb_aggr(buf, 3U, NULL, NULL, NULL) == -1);
    assert(aic_rx_demux_usb_aggr(buf, o - 1U, NULL, NULL, NULL) == -1);
    uint8_t zero[4] = {0};
    assert(aic_rx_demux_usb_aggr(zero, sizeof(zero), NULL, NULL, NULL) == -1);

    /* FromDS CCMP data frame: 8-byte IV, LLC/SNAP IPv4, 2-byte payload */
    uint8_t c[256], eth[64];
    size_t p = chunk_hdr(c, 0x08, 0x02, AIC_RX_HD_DECR_CCMP128) + 8U;
    const uint8_t llc[8] = {0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x00};
    memcpy(&c[p], llc, 8); c[p + 8] = 'h'; c[p + 9] = 'i';
    assert(aic_rx_chunk_to_eth_frames(c, p + 10U, eth, sizeof(eth), on_eth, NULL) == 1);
    assert(n_eth == 1 && last_len == 16U);
    assert(last_eth[0] == 0xA1 && last_eth[6] == 0xC3 && last_eth[12] == 0x08 && last_eth[13] == 0x00);
    assert(last_eth[14] == 'h' && last_eth[15] == 'i');
    /* the IV/LLC cut off, too short for the header, scratch too small: rejected */
    assert(aic_rx_chunk_to_eth_frames(c, p + 7U, eth, sizeof(eth), NULL, NULL) == -1);
    assert(aic_rx_chunk_to_eth_frames(c, AIC_RX_HWHDR_LEN + 23U, eth, sizeof(eth), NULL, NULL) == -1);
    assert(aic_rx_chunk_to_eth_frames(c, p + 10U, eth, 15U, NULL, NULL) == -1);
    /* a management frame is not data */
    chunk_hdr(c, 0x80, 0x00, 0);
    assert(aic_rx_chunk_to_eth_frames(c, 120U, eth, sizeof(eth), NULL, NULL) == 0);

    /* QoS A-MSDU with two subframes: the first padded to 4, the last not */
    p = chunk_hdr(c, 0x88, 0x02, 0);
    c[p] = 0x80; p += 2U;
    const uint8_t sub1[24] = {2, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 0, 10, 0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x00, 'a', 'b'};
    const uint8_t sub2[25] = {2, 3, 3, 3, 3, 3, 2, 4, 4, 4, 4, 4, 0, 11, 0xAA, 0xAA, 3, 0, 0, 0, 0x88, 0x8E, 'x', 'y', 'z'};
    memcpy(&c[p], sub1, 24); memcpy(&c[p + 24], sub2, 25);
    n_eth = 0;
    assert(aic_rx_chunk_to_eth_frames(c, p + 49U, eth, sizeof(eth), on_eth, NULL) == 2);
    assert(n_eth == 2 && last_len == 17U && last_eth[1] == 3 && last_eth[12] == 0x88 && last_eth[16] == 'z');
    /* a subframe length past the frame: rejected */
    assert(aic_rx_chunk_to_eth_frames(c, p + 48U, eth, sizeof(eth), NULL, NULL) == -1);

    /* MSG URB: two firmware prints, the first padded to 4 */
    aic_lmac_cmd_matcher_t mt;
    memset(&mt, 0, sizeof(mt));
    uint8_t urb[16] = {5, 0, AIC_USB_TYPE_CFG_PRINT, 0, 'a', 'b', 'c', 'd', 'e', 0, 0, 0, 3, 0, AIC_USB_TYPE_CFG_PRINT, 0};
    uint8_t urb2[19];
    memcpy(urb2, urb, 16); memcpy(&urb2[16], "xyz", 3);
    assert(aic_usb_dispatch_msg_urb_ex(&mt, urb2, sizeof(urb2), NULL, NULL, NULL) == 0);
    assert(mt.fw_print_count == 2U && mt.invalid_pkt_count == 0U);
    /* first packet longer than the URB: rejected and counted */
    assert(aic_usb_dispatch_msg_urb_ex(&mt, urb, 8U, NULL, NULL, NULL) == -1);
    assert(mt.invalid_pkt_count == 1U);

    printf("aic_framing_test: ok\n");
    return 0;
}
