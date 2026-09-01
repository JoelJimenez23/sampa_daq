/*
 * config.c - Read the TOML file and apply it to the hardware.
 *
 * Order of application (it matters; it is the same order btMCH_Click follows
 * in the Windows GUI):
 *
 *   1. [sequence] reset_sampa    -> reset through the CNC
 *   2. [pll]                     -> clocks
 *   3. [fpga.cnc] and [fpga.dm]  -> FPGA registers
 *   4. [[chip]] global           -> SAMPA global registers
 *   5. [[chip]] channels.all     -> broadcast to all 32 channels
 *   6. [[chip]] channels.N       -> individual channels, they override
 *   7. [sequence] soft_reset / bx_sync / event_trigger
 *
 * Needs tomlc99 (toml.c and toml.h) in this directory. See the README.
 */
#include "config.h"
#include "sampa_hw.h"
#include "sampa_regs.h"
#include "fpga_regs.h"
#include "toml.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Context, so we do not drag parameters through every function. */
typedef struct {
  int   verify;      /* read back after writing        */
  int   dry_run;     /* only print, touch no hardware  */
  int   errors;
  char *err;
  size_t errsz;
} ctx_t;

static void fail(ctx_t *c, const char *fmt, ...)
{
  va_list ap;
  if (c->err && c->errsz && c->errors == 0) {   /* keep only the first one */
    va_start(ap, fmt);
    vsnprintf(c->err, c->errsz, fmt, ap);
    va_end(ap);
  }
  c->errors++;
}

/* Read an integer key. Returns 0 if it does not exist. */
static int get_int(toml_table_t *t, const char *key, int64_t *out)
{
  toml_datum_t d = toml_int_in(t, key);
  if (!d.ok)
    return 0;
  *out = d.u.i;
  return 1;
}

static int get_bool(toml_table_t *t, const char *key, int def)
{
  toml_datum_t d = toml_bool_in(t, key);
  return d.ok ? d.u.b : def;
}

/* ---------------------------------------------------------------- PLL --- */

static void apply_pll(ctx_t *c, toml_table_t *root)
{
  static const char *names[PLL_NUM_OUT] = { "adc", "bx", "so", "rad_slvs", "aux" };
  toml_table_t *t = toml_table_in(root, "pll");
  int64_t v;
  unsigned i;
  int touched = 0;

  if (!t)
    return;

  if (c->dry_run) { printf("[pll] (dry-run)\n"); }
  else if (pll_begin() != SAMPA_OK) { fail(c, "could not start PLL reconfiguration"); return; }

  if (get_int(t, "M", &v)) {
    printf("  pll M = %ld\n", (long)v);
    if (!c->dry_run && pll_set_m((uint32_t)v) != SAMPA_OK) fail(c, "failed to set the PLL M counter");
    touched = 1;
  }
  if (get_int(t, "N", &v)) {
    printf("  pll N = %ld\n", (long)v);
    if (!c->dry_run && pll_set_n((uint32_t)v) != SAMPA_OK) fail(c, "failed to set the PLL N counter");
    touched = 1;
  }
  for (i = 0; i < PLL_NUM_OUT; i++) {
    if (get_int(t, names[i], &v)) {
      printf("  pll %s divider = %ld\n", names[i], (long)v);
      if (!c->dry_run && pll_set_div(i, (uint32_t)v) != SAMPA_OK)
        fail(c, "failed to set the PLL %s divider", names[i]);
      touched = 1;
    }
  }

  if (touched && !c->dry_run && pll_commit() != SAMPA_OK)
    fail(c, "the PLL is still busy after applying the changes");
}

/* --------------------------------------------------------------- FPGA --- */

/* Check that the value fits in the register. Without this, a 999 in an
 * 8-bit register was truncated on write -- (uint8_t)999 == 0xE7 -- and a
 * value nobody asked for got applied, without a single warning. A typo in
 * the TOML must hurt here, not in the chip. */
static int fits(ctx_t *c, const char *key, unsigned bits, int64_t v)
{
  int64_t max = (bits >= 63) ? INT64_MAX : (((int64_t)1 << bits) - 1);

  if (v < 0) {
    fail(c, "%s: the value %lld is negative", key, (long long)v);
    return 0;
  }
  if (v > max) {
    fail(c, "%s: %lld does not fit in %u bits (maximum %lld)", key,
         (long long)v, bits, (long long)max);
    return 0;
  }
  return 1;
}

/* FPGA registers that may be written. Copied from cnc_reg_RO[] and
 * dm_reg_RO[] in Form1.cs: the GUI marks everything else read-only and
 * paints its box grey. It is needed here because [fpga.*.raw] writes a
 * whole register by its number, bypassing the field table, and writing a
 * read-only counter would do nothing good.
 *
 * CNC 0,1,2 are the old slow control (SC_ADD/SC_DAT/SC_MASK): in Form1.cs
 * their constants are commented out, but the text box stays editable, so
 * they are kept. DM 25 is HPS_REG, normally written only by sampa_server;
 * the GUI also lets you poke it from the Debug tab. */
static const uint8_t cnc_rw[] = { 0, 1, 2, 3, 4, 7, 12, 16 };
static const uint8_t dm_rw[]  = { 0, 25, 38 };

#define CNC_REG_SIZE 17   /* cnc_reg_size in Form1.cs */
#define DM_REG_SIZE  63   /* dm_reg_size  in Form1.cs */

static int reg_writable(const char *block, unsigned long reg)
{
  const uint8_t *t = (strcmp(block, "cnc") == 0) ? cnc_rw : dm_rw;
  size_t n = (strcmp(block, "cnc") == 0) ? sizeof cnc_rw : sizeof dm_rw;
  size_t i;

  for (i = 0; i < n; i++)
    if (t[i] == reg)
      return 1;
  return 0;
}

/* [fpga.cnc.raw] / [fpga.dm.raw]: write a whole 32-bit word into a
 * register, by its number. This is the hex box on the GUI's "FPGA
 * registers" page, and the only way to reach the bits fpga_regs.csv cannot
 * name yet -- of SMP_CFG_REG, for instance, it only names three of them.
 *
 * It is applied BEFORE the named fields on purpose: that way you can set
 * the whole register at once and then tune one field on top, which is
 * read-modify-write. The other way round, the raw write would wipe out the
 * fine tuning. */
static void apply_fpga_raw(ctx_t *c, toml_table_t *block_tab,
                           const char *block)
{
  toml_table_t *t = toml_table_in(block_tab, "raw");
  unsigned off = (strcmp(block, "cnc") == 0) ? OFF_CNC : OFF_DM;
  unsigned tam = (strcmp(block, "cnc") == 0) ? CNC_REG_SIZE : DM_REG_SIZE;
  const char *key;
  int i;

  if (!t)
    return;

  printf("[fpga.%s.raw]\n", block);
  for (i = 0; (key = toml_key_in(t, i)) != NULL; i++) {
    unsigned long reg;
    char *end = NULL;
    int64_t v;

    reg = strtoul(key, &end, 0);
    if (end == key || *end != '\0') {
      fail(c, "[fpga.%s.raw] '%s' is not a register number", block, key);
      continue;
    }
    if (reg >= tam) {
      fail(c, "[fpga.%s.raw] register %lu does not exist (there are %u)",
           block, reg, tam);
      continue;
    }
    if (!reg_writable(block, reg)) {
      fail(c, "[fpga.%s.raw] register %lu is read-only", block, reg);
      continue;
    }
    if (!get_int(t, key, &v)) {
      fail(c, "[fpga.%s.raw] the value of register %lu is not an integer",
           block, reg);
      continue;
    }
    if (!fits(c, key, 32, v))
      continue;

    printf("  reg %-2lu             = 0x%08lX\n", reg, (unsigned long)v);
    if (!c->dry_run && fpga_write(off, (uint8_t)reg, (uint32_t)v) != SAMPA_OK)
      fail(c, "failed to write register %lu of %s", reg, block);
  }
}

static void apply_fpga_block(ctx_t *c, toml_table_t *fpga, const char *block)
{
  toml_table_t *t = toml_table_in(fpga, block);
  const char *key;
  int i;

  if (!t)
    return;

  apply_fpga_raw(c, t, block);

  printf("[fpga.%s]\n", block);
  for (i = 0; (key = toml_key_in(t, i)) != NULL; i++) {
    const fpga_field_t *f = fpga_find(block, key);

    if (strcmp(key, "raw") == 0)   /* apply_fpga_raw already did it */
      continue;
    int64_t v;

    if (!f) {
      fail(c, "unknown field '%s' in [fpga.%s]", key, block);
      continue;
    }
    if (f->read_only) {
      fail(c, "field '%s' is read-only", key);
      continue;
    }
    if (!get_int(t, key, &v)) {
      fail(c, "the value of '%s' is not an integer", key);
      continue;
    }
    if (!fits(c, key, f->bits, v))
      continue;

    printf("  %-18s = 0x%lX\n", key, (unsigned long)v);
    if (!c->dry_run &&
        fpga_field_write((const struct fpga_field *)f, (uint32_t)v) != SAMPA_OK)
      fail(c, "failed to write field '%s'", key);
  }
}

/* -------------------------------------------------------------- SAMPA --- */


static void apply_globals(ctx_t *c, toml_table_t *chip_tab, uint8_t chip)
{
  toml_table_t *t = toml_table_in(chip_tab, "global");
  const char *key;
  int i;

  if (!t)
    return;

  printf("  [global] chip %u\n", chip);
  for (i = 0; (key = toml_key_in(t, i)) != NULL; i++) {
    const sampa_reg_t *r = sampa_find_glb(key);
    int64_t v;
    int err;

    if (!r)              { fail(c, "unknown global register '%s'", key); continue; }
    if (r->read_only)    { fail(c, "register '%s' is read-only", key); continue; }
    if (!get_int(t, key, &v)) { fail(c, "the value of '%s' is not an integer", key); continue; }
    if (!fits(c, key, r->size, v)) continue;

    printf("    %-12s = 0x%02lX\n", key, (unsigned long)v);
    if (c->dry_run)
      continue;

    err = sampa_write_glob(chip, r->addr, (uint8_t)v);
    if (err) { fail(c, "failed writing %s: %s", key, sampa_strerror(err)); continue; }

    if (c->verify) {
      uint8_t readback;
      err = sampa_read_glob(chip, r->addr, &readback);
      if (err)
        fail(c, "failed reading %s back: %s", key, sampa_strerror(err));
      else if (readback != (uint8_t)v)
        fail(c, "%s: wrote 0x%02X but read back 0x%02X", key, (unsigned)v, readback);
    }
  }
}

/* Apply a table of channel registers. ch = 0..31, or broadcast. */
static void apply_channel_regs(ctx_t *c, toml_table_t *t, uint8_t chip,
                               uint8_t ch, int broadcast)
{
  const char *key;
  int i;

  for (i = 0; (key = toml_key_in(t, i)) != NULL; i++) {
    const sampa_reg_t *r = sampa_find_ch(key);
    int64_t v;
    int err;

    if (!r)           { fail(c, "unknown channel register '%s'", key); continue; }
    if (r->read_only) { fail(c, "register '%s' is read-only", key); continue; }
    if (!get_int(t, key, &v)) { fail(c, "the value of '%s' is not an integer", key); continue; }
    if (!fits(c, key, r->size, v)) continue;

    printf("    %-12s = 0x%04lX  (%s)\n", key, (unsigned long)v,
           broadcast ? "all channels" : "one channel");
    if (c->dry_run)
      continue;

    err = sampa_write_ch(chip, ch, broadcast, r->addr, (uint16_t)v);
    if (err)
      fail(c, "failed writing %s: %s", key, sampa_strerror(err));
  }
}

static void apply_channels(ctx_t *c, toml_table_t *chip_tab, uint8_t chip)
{
  toml_table_t *chans = toml_table_in(chip_tab, "channels");
  toml_table_t *sub;
  const char *key;
  int i;

  if (!chans)
    return;

  /* Broadcast first, so individual channels can override it. */
  sub = toml_table_in(chans, "all");
  if (sub) {
    printf("  [channels.all] chip %u\n", chip);
    apply_channel_regs(c, sub, chip, 0, 1);
  }

  for (i = 0; (key = toml_key_in(chans, i)) != NULL; i++) {
    long ch;
    char *end;

    if (strcmp(key, "all") == 0)
      continue;

    ch = strtol(key, &end, 10);
    if (*end != '\0' || ch < 0 || ch > 31) {
      fail(c, "'%s' is not a valid channel number (0-31 or 'all')", key);
      continue;
    }
    sub = toml_table_in(chans, key);
    if (!sub)
      continue;

    printf("  [channels.%ld] chip %u\n", ch, chip);
    apply_channel_regs(c, sub, chip, (uint8_t)ch, 0);
  }
}

/* ----------------------------------------------------------- sequence --- */

static void run_command(ctx_t *c, const char *name, uint32_t cmd)
{
  printf("  command: %s\n", name);
  if (c->dry_run)
    return;
  if (fpga_command(cmd) != SAMPA_OK)
    fail(c, "failed to send command %s", name);
}

/* -------------------------------------------------------------- public --- */

int config_apply(const char *path, int verify, int dry_run,
                 char *errbuf, size_t errsz)
{
  char parse_err[256];
  toml_table_t *root, *seq, *fpga;
  toml_array_t *chips;
  ctx_t c;
  FILE *fp;
  int i, n;

  memset(&c, 0, sizeof c);
  c.verify  = verify;
  c.dry_run = dry_run;
  c.err     = errbuf;
  c.errsz   = errsz;
  if (errbuf && errsz)
    errbuf[0] = '\0';

  fp = fopen(path, "r");
  if (!fp) {
    snprintf(errbuf, errsz, "could not open '%s'", path);
    return -1;
  }
  root = toml_parse_file(fp, parse_err, sizeof parse_err);
  fclose(fp);
  if (!root) {
    snprintf(errbuf, errsz, "TOML syntax error: %s", parse_err);
    return -1;
  }

  seq = toml_table_in(root, "sequence");

  /* 1. reset before configuring */
  if (seq && get_bool(seq, "reset_sampa", 0))
    run_command(&c, "SAMPA reset", CNC_CMD_SAMPA_RESET);

  /* 2. clocks */
  apply_pll(&c, root);

  /* 3. FPGA registers */
  fpga = toml_table_in(root, "fpga");
  if (fpga) {
    apply_fpga_block(&c, fpga, "cnc");
    apply_fpga_block(&c, fpga, "dm");
  }

  /* 4-6. the chips */
  chips = toml_array_in(root, "chip");
  n = chips ? toml_array_nelem(chips) : 0;
  for (i = 0; i < n; i++) {
    toml_table_t *chip_tab = toml_table_at(chips, i);
    int64_t addr = 0;

    if (!chip_tab)
      continue;
    if (!get_int(chip_tab, "address", &addr)) {
      fail(&c, "a [[chip]] block is missing 'address'");
      continue;
    }
    if (addr < 0 || addr > 15) {
      fail(&c, "address = %ld out of range (0-15)", (long)addr);
      continue;
    }

    printf("[[chip]] address = %ld\n", (long)addr);
    apply_globals(&c, chip_tab, (uint8_t)addr);
    apply_channels(&c, chip_tab, (uint8_t)addr);

    /* soft reset of the chip just configured (SAMPA CMD = 5) */
    if (seq && get_bool(seq, "soft_reset", 0)) {
      const sampa_reg_t *r = sampa_find_glb("CMD");
      printf("  soft reset of chip %ld\n", (long)addr);
      if (!dry_run && r && sampa_write_glob((uint8_t)addr, r->addr, 5) != SAMPA_OK)
        fail(&c, "soft reset of chip %ld failed", (long)addr);
    }
  }

  /* 7. sincronizacion final */
  if (seq) {
    if (get_bool(seq, "bx_sync", 0))
      run_command(&c, "bunch-crossing sync", CNC_CMD_BX_SYNC);
    if (get_bool(seq, "event_trigger", 0))
      run_command(&c, "event trigger", CNC_CMD_EVENT_TRIGGER);
  }

  toml_free(root);
  return c.errors;
}
