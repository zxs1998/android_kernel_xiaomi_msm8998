/*
 * Copyright (c) 2013,2016 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#if defined(AR9888_HEADERS_DEF)
#define AR9888 1

#define WLAN_HEADERS 1
#include "common_drv.h"
#include "AR9888/v2/soc_addrs.h"
#include "AR9888/v2/hw/apb_athr_wlan_map.h"
#include "AR9888/v2/hw/gpio_athr_wlan_reg.h"
#include "AR9888/v2/hw/rtc_soc_reg.h"
#include "AR9888/v2/hw/rtc_wlan_reg.h"
#include "AR9888/v2/hw/si_reg.h"
#include "AR9888/v2/extra/hw/pcie_local_reg.h"

#include "AR9888/v2/extra/hw/soc_core_reg.h"
#include "AR9888/v2/hw/soc_pcie_reg.h"
#include "AR9888/v2/extra/hw/ce_reg_csr.h"
#include "AR9888/v2/hw/ce_wrapper_reg_csr.h"

#include <AR9888/v2/hw/mac_descriptors/rx_attention.h>
#include <AR9888/v2/hw/mac_descriptors/rx_frag_info.h>
#include <AR9888/v2/hw/mac_descriptors/rx_msdu_start.h>
#include <AR9888/v2/hw/mac_descriptors/rx_msdu_end.h>
#include <AR9888/v2/hw/mac_descriptors/rx_mpdu_start.h>
#include <AR9888/v2/hw/mac_descriptors/rx_mpdu_end.h>
#include <AR9888/v2/hw/mac_descriptors/rx_ppdu_start.h>
#include <AR9888/v2/hw/mac_descriptors/rx_ppdu_end.h>

/* TBDXXX: Eventually, this Base Address will be defined in HW header files */
#define PCIE_LOCAL_BASE_ADDRESS 0x80000

#define FW_EVENT_PENDING_ADDRESS (SOC_CORE_BASE_ADDRESS+SCRATCH_3_ADDRESS)
#define DRAM_BASE_ADDRESS TARG_DRAM_START

/* Backwards compatibility -- TBDXXX */

#define MISSING 0

#define SYSTEM_SLEEP_OFFSET                     SOC_SYSTEM_SLEEP_OFFSET
#define WLAN_SYSTEM_SLEEP_OFFSET                SOC_SYSTEM_SLEEP_OFFSET
#define WLAN_RESET_CONTROL_OFFSET               SOC_RESET_CONTROL_OFFSET
#define CLOCK_CONTROL_OFFSET                    SOC_CLOCK_CONTROL_OFFSET
#define CLOCK_CONTROL_SI0_CLK_MASK              SOC_CLOCK_CONTROL_SI0_CLK_MASK
#define RESET_CONTROL_MBOX_RST_MASK             MISSING
#define RESET_CONTROL_SI0_RST_MASK              SOC_RESET_CONTROL_SI0_RST_MASK
#define GPIO_BASE_ADDRESS                       WLAN_GPIO_BASE_ADDRESS
#define GPIO_PIN0_OFFSET                        WLAN_GPIO_PIN0_ADDRESS
#define GPIO_PIN1_OFFSET                        WLAN_GPIO_PIN1_ADDRESS
#define GPIO_PIN0_CONFIG_MASK                   WLAN_GPIO_PIN0_CONFIG_MASK
#define GPIO_PIN1_CONFIG_MASK                   WLAN_GPIO_PIN1_CONFIG_MASK
#define SI_BASE_ADDRESS                         WLAN_SI_BASE_ADDRESS
#define SCRATCH_BASE_ADDRESS                    SOC_CORE_BASE_ADDRESS
#define LOCAL_SCRATCH_OFFSET                    0x18
#define CPU_CLOCK_OFFSET                        SOC_CPU_CLOCK_OFFSET
#define LPO_CAL_OFFSET                          SOC_LPO_CAL_OFFSET
#define GPIO_PIN10_OFFSET                       WLAN_GPIO_PIN10_ADDRESS
#define GPIO_PIN11_OFFSET                       WLAN_GPIO_PIN11_ADDRESS
#define GPIO_PIN12_OFFSET                       WLAN_GPIO_PIN12_ADDRESS
#define GPIO_PIN13_OFFSET                       WLAN_GPIO_PIN13_ADDRESS
#define CPU_CLOCK_STANDARD_LSB                  SOC_CPU_CLOCK_STANDARD_LSB
#define CPU_CLOCK_STANDARD_MASK                 SOC_CPU_CLOCK_STANDARD_MASK
#define LPO_CAL_ENABLE_LSB                      SOC_LPO_CAL_ENABLE_LSB
#define LPO_CAL_ENABLE_MASK                     SOC_LPO_CAL_ENABLE_MASK
#define ANALOG_INTF_BASE_ADDRESS                WLAN_ANALOG_INTF_BASE_ADDRESS
#define MBOX_BASE_ADDRESS                       MISSING
#define INT_STATUS_ENABLE_ERROR_LSB             MISSING
#define INT_STATUS_ENABLE_ERROR_MASK            MISSING
#define INT_STATUS_ENABLE_CPU_LSB               MISSING
#define INT_STATUS_ENABLE_CPU_MASK              MISSING
#define INT_STATUS_ENABLE_COUNTER_LSB           MISSING
#define INT_STATUS_ENABLE_COUNTER_MASK          MISSING
#define INT_STATUS_ENABLE_MBOX_DATA_LSB         MISSING
#define INT_STATUS_ENABLE_MBOX_DATA_MASK        MISSING
#define ERROR_STATUS_ENABLE_RX_UNDERFLOW_LSB    MISSING
#define ERROR_STATUS_ENABLE_RX_UNDERFLOW_MASK   MISSING
#define ERROR_STATUS_ENABLE_TX_OVERFLOW_LSB     MISSING
#define ERROR_STATUS_ENABLE_TX_OVERFLOW_MASK    MISSING
#define COUNTER_INT_STATUS_ENABLE_BIT_LSB       MISSING
#define COUNTER_INT_STATUS_ENABLE_BIT_MASK      MISSING
#define INT_STATUS_ENABLE_ADDRESS               MISSING
#define CPU_INT_STATUS_ENABLE_BIT_LSB           MISSING
#define CPU_INT_STATUS_ENABLE_BIT_MASK          MISSING
#define HOST_INT_STATUS_ADDRESS                 MISSING
#define CPU_INT_STATUS_ADDRESS                  MISSING
#define ERROR_INT_STATUS_ADDRESS                MISSING
#define ERROR_INT_STATUS_WAKEUP_MASK            MISSING
#define ERROR_INT_STATUS_WAKEUP_LSB             MISSING
#define ERROR_INT_STATUS_RX_UNDERFLOW_MASK      MISSING
#define ERROR_INT_STATUS_RX_UNDERFLOW_LSB       MISSING
#define ERROR_INT_STATUS_TX_OVERFLOW_MASK       MISSING
#define ERROR_INT_STATUS_TX_OVERFLOW_LSB        MISSING
#define COUNT_DEC_ADDRESS                       MISSING
#define HOST_INT_STATUS_CPU_MASK                MISSING
#define HOST_INT_STATUS_CPU_LSB                 MISSING
#define HOST_INT_STATUS_ERROR_MASK              MISSING
#define HOST_INT_STATUS_ERROR_LSB               MISSING
#define HOST_INT_STATUS_COUNTER_MASK            MISSING
#define HOST_INT_STATUS_COUNTER_LSB             MISSING
#define RX_LOOKAHEAD_VALID_ADDRESS              MISSING
#define WINDOW_DATA_ADDRESS                     MISSING
#define WINDOW_READ_ADDR_ADDRESS                MISSING
#define WINDOW_WRITE_ADDR_ADDRESS               MISSING
/* MAC descriptor */
#define RX_ATTENTION_0_PHY_DATA_TYPE_MASK       MISSING
#define RX_MSDU_END_8_LRO_ELIGIBLE_MASK         MISSING
#define RX_MSDU_END_8_LRO_ELIGIBLE_LSB          MISSING
#define RX_MSDU_END_8_L3_HEADER_PADDING_LSB     MISSING
#define RX_MSDU_END_8_L3_HEADER_PADDING_MASK    MISSING
#define RX_PPDU_END_ANTENNA_OFFSET_DWORD (RX_PPDU_END_19_RX_ANTENNA_OFFSET >> 2)
#define MSDU_LINK_EXT_3_TCP_OVER_IPV4_CHECKSUM_EN_MASK  MISSING
#define MSDU_LINK_EXT_3_TCP_OVER_IPV6_CHECKSUM_EN_MASK  MISSING
#define MSDU_LINK_EXT_3_UDP_OVER_IPV4_CHECKSUM_EN_MASK  MISSING
#define MSDU_LINK_EXT_3_UDP_OVER_IPV6_CHECKSUM_EN_MASK  MISSING
#define MSDU_LINK_EXT_3_TCP_OVER_IPV4_CHECKSUM_EN_LSB   MISSING
#define MSDU_LINK_EXT_3_TCP_OVER_IPV6_CHECKSUM_EN_LSB   MISSING
#define MSDU_LINK_EXT_3_UDP_OVER_IPV4_CHECKSUM_EN_LSB   MISSING
#define MSDU_LINK_EXT_3_UDP_OVER_IPV6_CHECKSUM_EN_LSB   MISSING
/* GPIO Register */

#define GPIO_ENABLE_W1TS_LOW_ADDRESS WLAN_GPIO_ENABLE_W1TS_LOW_ADDRESS
#define GPIO_PIN0_CONFIG_LSB         WLAN_GPIO_PIN0_CONFIG_LSB
#define GPIO_PIN0_PAD_PULL_LSB       WLAN_GPIO_PIN0_PAD_PULL_LSB
#define GPIO_PIN0_PAD_PULL_MASK      WLAN_GPIO_PIN0_PAD_PULL_MASK
/* CE descriptor */
#define CE_SRC_DESC_SIZE_DWORD         2
#define CE_DEST_DESC_SIZE_DWORD        2
#define CE_SRC_DESC_SRC_PTR_OFFSET_DWORD    0
#define CE_SRC_DESC_INFO_OFFSET_DWORD       1
#define CE_DEST_DESC_DEST_PTR_OFFSET_DWORD  0
#define CE_DEST_DESC_INFO_OFFSET_DWORD      1
#define CE_SRC_DESC_INFO_HOST_INT_DISABLE_MASK     MISSING
#define CE_SRC_DESC_INFO_HOST_INT_DISABLE_SHIFT    MISSING
#define CE_SRC_DESC_INFO_TARGET_INT_DISABLE_MASK   MISSING
#define CE_SRC_DESC_INFO_TARGET_INT_DISABLE_SHIFT  MISSING
#define CE_DEST_DESC_INFO_HOST_INT_DISABLE_MASK    MISSING
#define CE_DEST_DESC_INFO_HOST_INT_DISABLE_SHIFT   MISSING
#define CE_DEST_DESC_INFO_TARGET_INT_DISABLE_MASK  MISSING
#define CE_DEST_DESC_INFO_TARGET_INT_DISABLE_SHIFT MISSING
#if _BYTE_ORDER == _BIG_ENDIAN
#define CE_SRC_DESC_INFO_NBYTES_MASK               0xFFFF0000
#define CE_SRC_DESC_INFO_NBYTES_SHIFT              16
#define CE_SRC_DESC_INFO_GATHER_MASK               0x00008000
#define CE_SRC_DESC_INFO_GATHER_SHIFT              15
#define CE_SRC_DESC_INFO_BYTE_SWAP_MASK            0x00004000
#define CE_SRC_DESC_INFO_BYTE_SWAP_SHIFT           14
#define CE_SRC_DESC_INFO_META_DATA_MASK            0x00003FFF
#define CE_SRC_DESC_INFO_META_DATA_SHIFT           0
#else
#define CE_SRC_DESC_INFO_NBYTES_MASK               0x0000FFFF
#define CE_SRC_DESC_INFO_NBYTES_SHIFT              0
#define CE_SRC_DESC_INFO_GATHER_MASK               0x00010000
#define CE_SRC_DESC_INFO_GATHER_SHIFT              16
#define CE_SRC_DESC_INFO_BYTE_SWAP_MASK            0x00020000
#define CE_SRC_DESC_INFO_BYTE_SWAP_SHIFT           17
#define CE_SRC_DESC_INFO_META_DATA_MASK            0xFFFC0000
#define CE_SRC_DESC_INFO_META_DATA_SHIFT           18
#endif
#if _BYTE_ORDER == _BIG_ENDIAN
#define CE_DEST_DESC_INFO_NBYTES_MASK              0xFFFF0000
#define CE_DEST_DESC_INFO_NBYTES_SHIFT             16
#define CE_DEST_DESC_INFO_GATHER_MASK              0x00008000
#define CE_DEST_DESC_INFO_GATHER_SHIFT             15
#define CE_DEST_DESC_INFO_BYTE_SWAP_MASK           0x00004000
#define CE_DEST_DESC_INFO_BYTE_SWAP_SHIFT          14
#define CE_DEST_DESC_INFO_META_DATA_MASK           0x00003FFF
#define CE_DEST_DESC_INFO_META_DATA_SHIFT          0
#else
#define CE_DEST_DESC_INFO_NBYTES_MASK              0x0000FFFF
#define CE_DEST_DESC_INFO_NBYTES_SHIFT             0
#define CE_DEST_DESC_INFO_GATHER_MASK              0x00010000
#define CE_DEST_DESC_INFO_GATHER_SHIFT             16
#define CE_DEST_DESC_INFO_BYTE_SWAP_MASK           0x00020000
#define CE_DEST_DESC_INFO_BYTE_SWAP_SHIFT          17
#define CE_DEST_DESC_INFO_META_DATA_MASK           0xFFFC0000
#define CE_DEST_DESC_INFO_META_DATA_SHIFT          18
#endif

#define MY_TARGET_DEF AR9888_TARGETdef
#define MY_HOST_DEF AR9888_HOSTdef
#define MY_CEREG_DEF AR9888_CE_TARGETdef
#define MY_TARGET_BOARD_DATA_SZ AR9888_BOARD_DATA_SZ
#define MY_TARGET_BOARD_EXT_DATA_SZ AR9888_BOARD_EXT_DATA_SZ
#include "targetdef.h"
#include "hostdef.h"
#else
#include "common_drv.h"
#include "targetdef.h"
#include "hostdef.h"
struct targetdef_s *AR9888_TARGETdef;
struct hostdef_s *AR9888_HOSTdef;
#endif /*AR9888_HEADERS_DEF */
