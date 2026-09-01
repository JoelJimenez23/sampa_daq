/*
 * sampa_hw.h - Access to the SAMPA chip from the Linux running on the HPS.
 *
 * The path is:
 *
 *   this program --> h2f_lw bridge --> i2c_master block (FPGA) --> SAMPA chip
 *
 * None of this goes through the DDR3: 0xFF200000 is not memory, these are
 * registers inside the FPGA (memory-mapped I/O).
 */
#ifndef SAMPA_HW_H
#define SAMPA_HW_H

#include <stdint.h>

/* --- Lightweight HPS->FPGA bridge map -------------------------------------
 * Offsets follow the hps.h2f_lw_axi_master connections in hps.qsys.
 * (The Windows GUI sees these same blocks at 0x000/0x100/0x200/0x300, but
 * counted in WORDS and over the UART. Do not mix the two.)
 */
#define LW_BRIDGE_BASE   0xFF200000u
#define LW_BRIDGE_SPAN   0x00004000u

#define OFF_CNC          0x0000u   /* command_and_control                    */
#define OFF_DM           0x1000u   /* data_manager (used by sampa_server)    */
#define OFF_PLL          0x2000u   /* pll_reconfig                           */
#define OFF_I2C          0x3000u   /* i2c_master  <-- the one we care about  */

/* --- SAMPA global registers -----------------------------------------------
 * Only the ones needed for indirect access to the channel registers.
 * The full table with names is in sampa_regs.h (generated from the CSV).
 */
#define SMP_PMADDL       0x15   /* pedestal memory address, low byte          */
#define SMP_PMADDH       0x16   /* same, high byte                            */
#define SMP_CHRGADD      0x17   /* channel register address                   */
#define SMP_CHRGWDATL    0x18   /* data to write, low byte                    */
#define SMP_CHRGWDATH    0x19   /* data to write, top 5 bits                  */
#define SMP_CHRGCTL      0x1A   /* control: [7]inc [6]write [5]bcast [4:0]ch  */
#define SMP_CHRGRDATL    0x1B   /* data read back, low byte                   */
#define SMP_CHRGRDATH    0x1C   /* data read back, top 5 bits                 */

/* --- Error codes ---------------------------------------------------------- */
#define SAMPA_OK           0
#define SAMPA_ERR_NOTOPEN (-1)   /* sampa_open() was never called            */
#define SAMPA_ERR_OPEN    (-2)   /* could not open /dev/mem (root needed)    */
#define SAMPA_ERR_MMAP    (-3)   /* mmap of the bridge failed                */
#define SAMPA_ERR_TIMEOUT (-4)   /* i2c_master never finished the transfer   */
#define SAMPA_ERR_NACK    (-5)   /* the SAMPA did not answer (no ACK)        */
#define SAMPA_ERR_ARBLOST (-6)   /* arbitration lost on the I2C bus          */
#define SAMPA_ERR_RANGE   (-7)   /* chip/channel/register out of range       */

/* --- API ------------------------------------------------------------------ */

/* Open /dev/mem and map the bridge. Returns SAMPA_OK or an error code.
 * Necesita permisos de root. */
int  sampa_open(void);
void sampa_close(void);

/* Registros globales (8 bits). chip 0-15, reg 0-63. */
int  sampa_write_glob(uint8_t chip, uint8_t reg, uint8_t val);
int  sampa_read_glob (uint8_t chip, uint8_t reg, uint8_t *val);

/* Channel registers (up to 13 bits). They are reached indirectly, by
 * writing several global registers in the right order.
 * broadcast != 0 writes all 32 channels at once and ignores 'ch'. */
int  sampa_write_ch(uint8_t chip, uint8_t ch, int broadcast,
                    uint8_t reg, uint16_t val);
int  sampa_read_ch (uint8_t chip, uint8_t ch, uint8_t reg, uint16_t *val);

/* Human-readable text for an error code. */
const char *sampa_strerror(int err);

/* Enable stderr tracing of every I2C transaction (for debugging). */
void sampa_set_verbose(int on);

/* --- The FPGA's own registers (CNC and DM blocks) -------------------------
 * Direct access over the bridge: these are memory writes, with no I2C in
 * between, so there is nothing to wait for.
 */
/* Data Manager words needed to train the links. */
#define DM_STATUS_REG    26   /* [10:0] sync flag per link                  */
#define DM_SYNC0_REG     27   /* 27..37: sync-loss counter per link         */
#define DM_EDGE_SEL_REG  38   /* [10:0] edge per link, [21:11] delay        */
#define DM_NUM_LINKS     11

int fpga_read (unsigned block_off, uint8_t reg, uint32_t *val);
int fpga_write(unsigned block_off, uint8_t reg, uint32_t val);

/* Named field (see fpga_regs.csv). Does a read-modify-write, just like
 * cnc_write_single_pos/dm_write_single_pos in Form1.cs. */
struct fpga_field;
int fpga_field_write(const struct fpga_field *f, uint32_t val);
int fpga_field_read (const struct fpga_field *f, uint32_t *val);

/* CNC commands (register 3, bits 0-15). These are actions, not config. */
#define CNC_CMD_SAMPA_RESET   2
#define CNC_CMD_EVENT_TRIGGER 3
#define CNC_CMD_HEARTBEAT     4
#define CNC_CMD_BX_SYNC       5
#define CNC_CMD_CLEAR_ERRORS  7
int fpga_command(uint32_t cmd);

/* --- PLL: the SAMPA clocks -----------------------------------------------
 * Sequence: pll_begin() -> whichever pll_set_*() are needed -> pll_commit().
 * The divider is encoded as in pllWriteChange_Click of Form1.cs.
 * Outputs: 0 = ADC, 1 = BX, 2 = SO, 3 = rad_slvs (not wired), 4 = spare.
 */
#define PLL_OUT_ADC  0
#define PLL_OUT_BX   1
#define PLL_OUT_SO   2
#define PLL_NUM_OUT  5

int pll_begin(void);
int pll_set_m(uint32_t m);
int pll_set_n(uint32_t n);
int pll_set_div(unsigned output, uint32_t div);
int pll_commit(void);
int pll_get_div(unsigned output, uint32_t *div);

#endif /* SAMPA_HW_H */
