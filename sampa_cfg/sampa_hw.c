/*
 * sampa_hw.c - Access to the SAMPA chip through the FPGA's i2c_master.
 *
 * IMPORTANT - why this code waits and the Windows GUI does not:
 *
 *   The PC program (Form1.cs) fires I2C commands back to back without
 *   checking anything. It works by accident: each of its writes travels over
 *   the UART at 115200 baud and takes about 700 us, while the I2C
 *   transaction takes about 40 us. The slowness of the UART gave it plenty
 *   of slack.
 *
 *   From the HPS across the bridge a write takes ~100 ns, some 7000 times
 *   less. Copying that code as-is would clobber the previous transaction
 *   before it finished. That is why here we ALWAYS wait for the i2c_master
 *   to finish (i2c_wait_done) before issuing the next command.
 */
#include "sampa_hw.h"
#include "fpga_regs.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

/* --- i2c_master registers (ip/i2c_master/i2c_master_top.vhd) -------------
 * The slave is declared 'addressUnits WORDS', so on the bridge (which is
 * byte-addressed) each register lands every 4 bytes. Using a uint32_t
 * pointer, the index already does that multiplication.
 */
#define I2C_PRE   0   /* rw  clock prescaler; default 13 -> 960 kHz        */
#define I2C_CTR   1   /* rw  [1] core_en, [0] ien; default "10"            */
#define I2C_ADD   2   /* rw  [9:6] chip, [5:0] register                    */
#define I2C_TX    3   /* rw  byte to transmit                              */
#define I2C_RX    4   /* r   byte received                                 */
#define I2C_COM   5   /* r/w command register                              */
#define I2C_STA   6   /* r   status register                               */

/* COM_REG: the FPGA state machine does the 10-bit I2C addressing on its
 * own (two address bytes + data). We only issue the command. */
#define COM_RD10  0x80   /* read  with 10-bit addressing  */
#define COM_WR10  0x40   /* write with 10-bit addressing  */

/* CTR_REG */
#define CTR_EN    (1u << 1)   /* turn the core on                  */
#define CTR_IEN   (1u << 0)   /* interrupts; we do not use them    */

/* Prescaler for SCL ~960 kHz with the FPGA's 50 MHz clock. */
#define I2C_PRE_960K  13

/* STA_REG */
#define STA_RXACK (1u << 4)   /* 1 = the slave did NOT answer (NACK) */
#define STA_BUSY  (1u << 3)
#define STA_AL    (1u << 2)   /* arbitration lost */
#define STA_TIP   (1u << 1)   /* transfer in progress */

/* Maximum polling iterations. A 10-bit transaction at 960 kHz takes about
 * 40 us; each iteration is one read across the bridge (~0.1-0.2 us), so
 * roughly 400 iterations. The margin is huge on purpose: if it runs out,
 * something is genuinely broken (FPGA not programmed, clock stopped, bus
 * stuck). */
#define I2C_MAX_POLL  2000000

/* Polling iterations waiting for the PLL to finish reconfiguring. Each
 * iteration is one read across the bridge (~100 ns), so this is tens of
 * milliseconds of margin: plenty, and without sleeping. */
#define PLL_MAX_POLL  200000

static volatile uint32_t *bridge;   /* mapped base of the bridge */
static volatile uint32_t *i2c;      /* i2c_master block          */
static int mem_fd = -1;
static int verbose;

void sampa_set_verbose(int on) { verbose = on; }

int sampa_open(void)
{
  void *p;

  if (i2c)                      /* already open */
    return SAMPA_OK;

  mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (mem_fd < 0)
    return SAMPA_ERR_OPEN;

  p = mmap(NULL, LW_BRIDGE_SPAN, PROT_READ | PROT_WRITE, MAP_SHARED,
           mem_fd, LW_BRIDGE_BASE);
  if (p == MAP_FAILED) {
    close(mem_fd);
    mem_fd = -1;
    return SAMPA_ERR_MMAP;
  }

  bridge = (volatile uint32_t *)p;
  /* OFF_I2C is in bytes and bridge is uint32_t* -> divide by 4 */
  i2c    = bridge + (OFF_I2C / sizeof(uint32_t));

  /* Set prescaler and core explicitly instead of trusting the HDL reset.
   * On the board we found PRE = 0x80F0, which leaves SCL at about 300 Hz:
   * transactions come out wrong and EVERY read returns 0xFF without
   * reporting an error. With PRE = 13 they work again. The prescaler may
   * only be touched with the core stopped, hence the three writes. */
  i2c[I2C_CTR] = 0;
  i2c[I2C_PRE] = I2C_PRE_960K;
  i2c[I2C_CTR] = CTR_EN;

  return SAMPA_OK;
}

void sampa_close(void)
{
  if (bridge) {
    munmap((void *)bridge, LW_BRIDGE_SPAN);
    bridge = NULL;
    i2c    = NULL;
  }
  if (mem_fd >= 0) {
    close(mem_fd);
    mem_fd = -1;
  }
}

/*
 * Wait for the i2c_master to finish the command in flight.
 *
 * When the state machine is done (or loses arbitration) it clears bits 7..1
 * of COM_REG -- see the done_s state in i2c_master_top.vhd. So COM_REG
 * going back to zero is the "I have finished" signal.
 *
 * is_write says whether the command was a write. It is needed because the
 * RXACK bit of STA_REG only means "the slave did not answer" AFTER a write.
 * In i2c_master_byte_ctrl.vhd the st_ack state always does
 * "ack_out <= core_rxd", no matter what; and at the end of a read the
 * master itself sends a NACK (rd3_s sets ack <= '1') to close the transfer.
 * So after a read, RXACK is ALWAYS 1 and means nothing. Checking it there
 * would make every correct read fail.
 */
static int i2c_wait_done(int is_write)
{
  uint32_t sta;
  long i;

  for (i = 0; i < I2C_MAX_POLL; i++) {
    if ((i2c[I2C_COM] & 0xFEu) == 0)
      break;
  }
  if (i == I2C_MAX_POLL)
    return SAMPA_ERR_TIMEOUT;

  sta = i2c[I2C_STA];
  if (sta & STA_AL)
    return SAMPA_ERR_ARBLOST;
  if (is_write && (sta & STA_RXACK))   /* solo vale tras escribir */
    return SAMPA_ERR_NACK;
  return SAMPA_OK;
}

int sampa_write_glob(uint8_t chip, uint8_t reg, uint8_t val)
{
  int err;

  if (!i2c)
    return SAMPA_ERR_NOTOPEN;
  if (chip > 15 || reg > 63)
    return SAMPA_ERR_RANGE;

  i2c[I2C_ADD] = ((uint32_t)(chip & 0x0F) << 6) | (reg & 0x3F);
  i2c[I2C_TX]  = val;
  i2c[I2C_COM] = COM_WR10;

  err = i2c_wait_done(1);
  if (verbose)
    fprintf(stderr, "  i2c wr chip=%u reg=0x%02X val=0x%02X -> %s\n",
            chip, reg, val, sampa_strerror(err));
  return err;
}

int sampa_read_glob(uint8_t chip, uint8_t reg, uint8_t *val)
{
  int err;

  if (!i2c)
    return SAMPA_ERR_NOTOPEN;
  if (chip > 15 || reg > 63)
    return SAMPA_ERR_RANGE;

  i2c[I2C_ADD] = ((uint32_t)(chip & 0x0F) << 6) | (reg & 0x3F);
  i2c[I2C_COM] = COM_RD10;

  err = i2c_wait_done(0);
  if (err == SAMPA_OK)
    *val = (uint8_t)(i2c[I2C_RX] & 0xFF);

  if (verbose)
    fprintf(stderr, "  i2c rd chip=%u reg=0x%02X -> 0x%02X %s\n",
            chip, reg, (err == SAMPA_OK) ? *val : 0, sampa_strerror(err));
  return err;
}

/*
 * Channel registers: the SAMPA does not expose them directly. Five global
 * registers must be used in this exact order (same as sampaWriteRegCh and
 * sampaReadRegCh in Form1.cs).
 */
int sampa_write_ch(uint8_t chip, uint8_t ch, int broadcast,
                   uint8_t reg, uint16_t val)
{
  int err;
  uint8_t ctl;

  if (ch > 31)
    return SAMPA_ERR_RANGE;

  err = sampa_write_glob(chip, SMP_CHRGADD, reg);
  if (err) return err;
  err = sampa_write_glob(chip, SMP_CHRGWDATL, (uint8_t)(val & 0xFF));
  if (err) return err;
  err = sampa_write_glob(chip, SMP_CHRGWDATH, (uint8_t)((val >> 8) & 0x1F));
  if (err) return err;

  ctl = (uint8_t)((1u << 6)                          /* escribir */
                | ((broadcast ? 1u : 0u) << 5)       /* to every channel    */
                | (ch & 0x1F));
  return sampa_write_glob(chip, SMP_CHRGCTL, ctl);
}

int sampa_read_ch(uint8_t chip, uint8_t ch, uint8_t reg, uint16_t *val)
{
  int err;
  uint8_t lo, hi;

  if (ch > 31)
    return SAMPA_ERR_RANGE;

  err = sampa_write_glob(chip, SMP_CHRGADD, reg);
  if (err) return err;
  /* bit 6 clear = read mode, bit 5 clear = no broadcast */
  err = sampa_write_glob(chip, SMP_CHRGCTL, (uint8_t)(ch & 0x1F));
  if (err) return err;

  err = sampa_read_glob(chip, SMP_CHRGRDATL, &lo);
  if (err) return err;
  err = sampa_read_glob(chip, SMP_CHRGRDATH, &hi);
  if (err) return err;

  *val = (uint16_t)(lo | ((hi & 0x1F) << 8));
  return SAMPA_OK;
}

const char *sampa_strerror(int err)
{
  switch (err) {
  case SAMPA_OK:           return "ok";
  case SAMPA_ERR_NOTOPEN:  return "sampa_open() was never called";
  case SAMPA_ERR_OPEN:     return "could not open /dev/mem (root required)";
  case SAMPA_ERR_MMAP:     return "mmap of the h2f_lw bridge failed";
  case SAMPA_ERR_TIMEOUT:  return "the i2c_master did not respond (FPGA not programmed? clock stopped?)";
  case SAMPA_ERR_NACK:     return "the SAMPA did not answer (wrong chip address? no clock? no power?)";
  case SAMPA_ERR_ARBLOST:  return "arbitration lost on the I2C bus";
  case SAMPA_ERR_RANGE:    return "chip/channel/register out of range";
  default:                 return "unknown error";
  }
}

/* =========================================================================
 * The FPGA's own registers (CNC and DM)
 *
 * There is no I2C here: it is a memory write across the bridge, about
 * 100 ns. So nothing needs waiting for, unlike with the SAMPA.
 * ========================================================================= */

int fpga_read(unsigned block_off, uint8_t reg, uint32_t *val)
{
  if (!bridge)
    return SAMPA_ERR_NOTOPEN;
  *val = bridge[block_off / sizeof(uint32_t) + reg];
  return SAMPA_OK;
}

int fpga_write(unsigned block_off, uint8_t reg, uint32_t val)
{
  if (!bridge)
    return SAMPA_ERR_NOTOPEN;
  bridge[block_off / sizeof(uint32_t) + reg] = val;
  if (verbose)
    fprintf(stderr, "  fpga wr blk=0x%04X reg=%u val=0x%08X\n",
            block_off, reg, val);
  return SAMPA_OK;
}

/* Translate the table's block name into an offset inside the bridge. */
static int block_offset(const char *block, unsigned *off)
{
  if (strcmp(block, "cnc") == 0)      *off = OFF_CNC;
  else if (strcmp(block, "dm") == 0)  *off = OFF_DM;
  else if (strcmp(block, "pll") == 0) *off = OFF_PLL;
  else return SAMPA_ERR_RANGE;
  return SAMPA_OK;
}

int fpga_field_write(const struct fpga_field *fp, uint32_t val)
{
  const fpga_field_t *f = (const fpga_field_t *)fp;
  uint32_t cur, mask;
  unsigned off;
  int err;

  err = block_offset(f->block, &off);
  if (err) return err;

  err = fpga_read(off, f->reg, &cur);
  if (err) return err;

  /* Careful with f->bits == 32: 1u<<32 is undefined behaviour in C. */
  mask = (f->bits >= 32) ? 0xFFFFFFFFu : ((1u << f->bits) - 1u);
  cur  = (cur & ~(mask << f->pos)) | ((val & mask) << f->pos);

  return fpga_write(off, f->reg, cur);
}

int fpga_field_read(const struct fpga_field *fp, uint32_t *val)
{
  const fpga_field_t *f = (const fpga_field_t *)fp;
  uint32_t cur, mask;
  unsigned off;
  int err;

  err = block_offset(f->block, &off);
  if (err) return err;

  err = fpga_read(off, f->reg, &cur);
  if (err) return err;

  mask = (f->bits >= 32) ? 0xFFFFFFFFu : ((1u << f->bits) - 1u);
  *val = (cur >> f->pos) & mask;
  return SAMPA_OK;
}

int fpga_command(uint32_t cmd)
{
  const fpga_field_t *f = fpga_find("cnc", "command");
  if (!f)
    return SAMPA_ERR_RANGE;
  return fpga_field_write((const struct fpga_field *)f, cmd);
}

/* =========================================================================
 * PLL (reconfiguration of the SAMPA clocks)
 * ========================================================================= */

#define PLL_POLL     0x0000   /* 1 = modo sondeo                            */
#define PLL_STATUS   0x0001   /* 1 = listo, 0 = ocupado                     */
#define PLL_START    0x0002   /* write to apply the changes                 */
#define PLL_N        0x0003   /* divisor (denominador)                      */
#define PLL_M        0x0004   /* multiplicador (numerador)                  */
#define PLL_C_WRITE  0x0005   /* C counter: [22:18] output, [15:8] hi, [7:0] lo */
#define PLL_C_READ   0x000A   /* read back the C counter of output 0        */

/*
 * Encode a divider the way the Altera PLL expects it: half in the high
 * count and half in the low count (divider = hi + lo). Same as Form1.cs.
 */
static uint32_t pll_encode_div(uint32_t div, int output)
{
  uint32_t v;

  if (div <= 1)
    v = (1u << 16);                                    /* bypass */
  else if (div & 1u)                                   /* division impar */
    v = (1u << 17)
      | ((((div >> 1) + 1u) & 0xFFu) << 8)
      | ((div >> 1) & 0xFFu);
  else
    v = (((div >> 1) & 0xFFu) << 8) | ((div >> 1) & 0xFFu);

  if (output >= 0)
    v |= ((uint32_t)output << 18);
  return v;
}

int pll_begin(void)          { return fpga_write(OFF_PLL, PLL_POLL, 1); }
int pll_set_m(uint32_t m)    { return fpga_write(OFF_PLL, PLL_M, pll_encode_div(m, -1)); }
int pll_set_n(uint32_t n)    { return fpga_write(OFF_PLL, PLL_N, pll_encode_div(n, -1)); }

int pll_set_div(unsigned output, uint32_t div)
{
  if (output >= PLL_NUM_OUT)
    return SAMPA_ERR_RANGE;
  return fpga_write(OFF_PLL, PLL_C_WRITE, pll_encode_div(div, (int)output));
}

int pll_commit(void)
{
  uint32_t status = 0;
  long i;
  int err = fpga_write(OFF_PLL, PLL_START, 1);
  if (err) return err;

  /* We must POLL, not read once: the PLL reconfiguration takes time, and
   * reading the status immediately after the start catches it busy and
   * fails a change that is actually fine. The GUI never notices because
   * each of its UART transactions takes ~700 us, which is wait enough; over
   * the bridge it is ~100 ns and that margin does not exist. Same problem
   * that i2c_wait_done solves for the I2C. */
  for (i = 0; i < PLL_MAX_POLL; i++) {
    err = fpga_read(OFF_PLL, PLL_STATUS, &status);
    if (err) return err;
    if (status != 0)          /* 0 = sigue ocupado */
      return SAMPA_OK;
  }
  return SAMPA_ERR_TIMEOUT;
}

int pll_get_div(unsigned output, uint32_t *div)
{
  uint32_t raw = 0;
  int err;

  if (output >= PLL_NUM_OUT)
    return SAMPA_ERR_RANGE;

  err = fpga_read(OFF_PLL, (uint8_t)(PLL_C_READ + output), &raw);
  if (err) return err;

  *div = ((raw >> 8) & 0xFFu) + (raw & 0xFFu);   /* divisor = hi + lo */
  if (*div == 0)
    *div = 1;                                     /* bypass activo */
  return SAMPA_OK;
}
