/*
 * sampa_cfg - command-line tool to talk to the SAMPA from the Linux
 *             running on the HPS.
 *
 * It started life as a way to CHECK that the path works; the TOML
 * configuration reader is built on top of these same functions.
 *
 * It must be run as root: it uses /dev/mem.
 */
#include "sampa_hw.h"
#include "sampa_regs.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog)
{
  printf(
    "Usage: %s [-v] <command> [arguments]\n"
    "\n"
    "  probe    [chip]                   read HWADD and check the path\n"
    "  dump     [chip]                   dump every global register\n"
    "  dumpch   <chip> <channel>         dump the registers of one channel\n"
    "  read     <chip> <NAME>            read a global register\n"
    "  write    <chip> <NAME> <value>    write a global register\n"
    "  readch   <chip> <channel> <NAME>  read a channel register\n"
    "  writech  <chip> <channel|all> <NAME> <value>\n"
    "  regs                              list the known register names\n"
    "  fixsync  [ms]                     train the serial links (window, 1000)\n"
    "  apply    <file.toml>              apply a configuration file\n"
    "\n"
    "  -v         trace every I2C transaction\n"
    "  --verify   read each register back after writing it (apply only)\n"
    "  --dry-run  only show what it would do, touching no hardware\n"
    "\n"
    "Values may be decimal or hexadecimal (0x..).\n"
    "chip = 0..15 (the SAMPA HWADD address), channel = 0..31.\n",
    prog);
}

static long num(const char *s)
{
  return strtol(s, NULL, 0);   /* base 0: acepta 10 y 0x0A */
}

static int cmd_probe(uint8_t chip)
{
  uint8_t v;
  int err;

  printf("Opening the h2f_lw bridge at 0x%08X...\n", LW_BRIDGE_BASE);
  printf("Reading HWADD of chip %u through the i2c_master (offset 0x%04X)...\n",
         chip, OFF_I2C);

  err = sampa_read_glob(chip, 0x00, &v);   /* 0x00 = HWADD */
  if (err) {
    printf("\n  FALLO: %s\n", sampa_strerror(err));
    return 1;
  }

  printf("\n  HWADD = %u\n", v);
  if (v == chip) {
    printf("  OK: the chip answers and its address matches.\n");
    printf("  The Linux -> bridge -> i2c_master -> SAMPA path works.\n");
    return 0;
  }
  printf("  WARNING: expected %u but the chip says %u.\n", chip, v);
  printf("  Check the SAMPA address pins, or try a different chip number.\n");
  return 1;
}

/* ---------------------------------------------------------------------------
 * fixsync: for each serial link, pick the sampling edge and delay at which it
 * locks and does NOT lose synchronisation.
 *
 * The GUI's "Fix sync" button blindly flips the edge bit of the failing link,
 * once per click and without checking whether it helped. If the delay was the
 * problem, the next click puts it back where it was: that is why you end up
 * clicking the button over and over. Here the FOUR combinations
 * (edge x delay) are tried, each is measured, and one is chosen. It converges
 * in a single pass.
 *
 * The sync-loss counters are per link, so the four tests serve all eleven
 * links at once: four windows and done. And since the sync bits belong to the
 * deserialiser, there is no need to touch the SAMPA or stop the acquisition;
 * only EDGE_SEL_REG is written.
 *
 * WARNING: this command rewrites SOCFG and the CHEN registers to run its
 * sweep, and does not restore them. On a bench with fewer than eleven links
 * wired, prefer to set EDGE_SEL_REG by hand.
 * ------------------------------------------------------------------------- */

#define SMP_CMD       0x0E   /* SAMPA command register                 */
#define SMP_CMD_SYNC  0x06   /* re-emit the sync pattern               */

#define EDGE_MASK   0x000007FFu   /* [10:0]  edge per link      */
#define DELAY_MASK  0x003FF800u   /* [21:11] delay per link     */

static int links_snapshot(uint32_t *status, uint32_t *losses)
{
  int i, err;

  err = fpga_read(OFF_DM, DM_STATUS_REG, status);
  if (err)
    return err;
  for (i = 0; i < DM_NUM_LINKS; i++) {
    err = fpga_read(OFF_DM, (uint8_t)(DM_SYNC0_REG + i), &losses[i]);
    if (err)
      return err;
  }
  return SAMPA_OK;
}

/* Measure one combination: write it, SEND THE SYNC TO THE CHIP, let it
 * settle, and see whether each link locks and holds without losing sync.
 *
 * The sync (SAMPA CMD register = 6) is not optional: changing the edge or the
 * delay drops the lock, and the deserialiser does not come back on its own.
 * Without this write, the first combination measured inherits whatever lock
 * was already there and looks good by accident, while every other one always
 * looks bad. It would also leave the links down at the end. */
static int probe_combo(uint32_t orig, int edge, int delay, unsigned window_ms,
                       unsigned settle_ms, int *synced, uint32_t *lost)
{
  uint32_t val, sta0, sta1;
  uint32_t l0[DM_NUM_LINKS], l1[DM_NUM_LINKS];
  int i, err;

  val = orig & ~(EDGE_MASK | DELAY_MASK);
  if (edge)
    val |= EDGE_MASK;
  if (delay)
    val |= DELAY_MASK;

  err = fpga_write(OFF_DM, DM_EDGE_SEL_REG, val);
  if (err)
    return err;

  err = sampa_write_glob(0, SMP_CMD, SMP_CMD_SYNC);
  if (err)
    return err;

  usleep((useconds_t)settle_ms * 1000);
  err = links_snapshot(&sta0, l0);
  if (err)
    return err;
  usleep((useconds_t)window_ms * 1000);
  err = links_snapshot(&sta1, l1);
  if (err)
    return err;

  for (i = 0; i < DM_NUM_LINKS; i++) {
    lost[i] = l1[i] - l0[i];
    /* 0 = ni engancho, 1 = engancho pero se cae, 2 = estable */
    if (!((sta0 >> i) & 1) && !((sta1 >> i) & 1) && lost[i] == 0)
      synced[i] = 0;
    else if (((sta0 >> i) & 1) && ((sta1 >> i) & 1) && lost[i] == 0)
      synced[i] = 2;
    else
      synced[i] = 1;
  }
  return SAMPA_OK;
}

/* Get the links locked again with whatever EDGE_SEL_REG currently holds. */
static void resync(void)
{
  sampa_write_glob(0, SMP_CMD, SMP_CMD_SYNC);
}

static int cmd_fixsync(unsigned window_ms)
{
  uint32_t orig, final_val, sta;
  uint32_t lost[4][DM_NUM_LINKS];
  int st[4][DM_NUM_LINKS];
  int combo, i, err, nlinks = DM_NUM_LINKS, buenos = 0, imposibles = 0;
  int pick[DM_NUM_LINKS];
  unsigned settle_ms = 500;
  uint8_t socfg;
  static const char *cab[4] = {"fl0/rt0", "fl0/rt1", "fl1/rt0", "fl1/rt1"};
  /* measurement and column order: (0,0) (0,1) (1,0) (1,1) */
  static const int ed[4] = {0, 0, 1, 1};
  static const int dl[4] = {0, 1, 0, 1};

  err = fpga_read(OFF_DM, DM_EDGE_SEL_REG, &orig);
  if (err) {
    printf("could not read EDGE_SEL_REG: %s\n", sampa_strerror(err));
    return 1;
  }

  /* Cuantos enlaces conduce el chip. Si el I2C no contesta, probamos todos. */
  if (sampa_read_glob(0, 0x12, &socfg) == SAMPA_OK && (socfg & 0x0F) > 0
      && (socfg & 0x0F) <= DM_NUM_LINKS)
    nlinks = socfg & 0x0F;
  else
    printf("warning: could not read SOCFG, trying all %d links\n", nlinks);

  printf("EDGE_SEL_REG de partida : 0x%08X\n", orig);
  printf("links driven by the chip: %d\n", nlinks);
  printf("midiendo 4 combinaciones (%u ms de asiento + %u ms de ventana)...\n\n",
         settle_ms, window_ms);

  for (combo = 0; combo < 4; combo++) {
    err = probe_combo(orig, ed[combo], dl[combo], window_ms, settle_ms,
                      st[combo], lost[combo]);
    if (err) {
      printf("fallo midiendo: %s\n", sampa_strerror(err));
      fpga_write(OFF_DM, DM_EDGE_SEL_REG, orig);   /* dejarlo como estaba */
      resync();
      return 1;
    }
  }

  /* For each link, the first stable combination. */
  final_val = orig & ~(EDGE_MASK | DELAY_MASK);
  for (i = 0; i < nlinks; i++) {
    pick[i] = -1;
    for (combo = 0; combo < 4; combo++)
      if (st[combo][i] == 2) {
        pick[i] = combo;
        break;
      }
    if (pick[i] < 0) {
      final_val |= orig & ((1u << i) | (1u << (11 + i)));  /* como estaba */
      imposibles++;
    } else {
      if (ed[pick[i]])
        final_val |= 1u << i;
      if (dl[pick[i]])
        final_val |= 1u << (11 + i);
      buenos++;
    }
  }
  /* Los enlaces que el chip no conduce se quedan como estaban. */
  for (i = nlinks; i < DM_NUM_LINKS; i++)
    final_val |= orig & ((1u << i) | (1u << (11 + i)));

  /* If every chosen link agrees on the same combination, write the EXACT
   * value that was measured instead of a per-link mixture. The bits of the
   * links nobody uses were also part of the measured state, and there is no
   * reason to assume they do not matter. */
  {
    int common = -1, mixed = 0;
    for (i = 0; i < nlinks; i++) {
      if (pick[i] < 0)
        continue;
      if (common < 0)
        common = pick[i];
      else if (pick[i] != common)
        mixed = 1;
    }
    if (common >= 0 && !mixed) {
      final_val = orig & ~(EDGE_MASK | DELAY_MASK);
      if (ed[common])
        final_val |= EDGE_MASK;
      if (dl[common])
        final_val |= DELAY_MASK;
      printf("(every good link agrees on %s: applying that state as-is)\n",
             cab[common]);
    }
  }

  err = fpga_write(OFF_DM, DM_EDGE_SEL_REG, final_val);
  if (err) {
    printf("could not write EDGE_SEL_REG: %s\n", sampa_strerror(err));
    return 1;
  }
  resync();

  printf("  link    %-8s %-8s %-8s %-8s  chosen\n",
         cab[0], cab[1], cab[2], cab[3]);
  for (i = 0; i < nlinks; i++) {
    printf("    %2d  ", i);
    for (combo = 0; combo < 4; combo++) {
      char cel[12];
      if (st[combo][i] == 2)
        snprintf(cel, sizeof cel, "estable");
      else if (st[combo][i] == 1)
        snprintf(cel, sizeof cel, "cae x%u", lost[combo][i]);
      else
        snprintf(cel, sizeof cel, "-");
      printf("%-8s ", cel);
    }
    if (pick[i] < 0)
      printf(" NINGUNA\n");
    else
      printf(" %s\n", cab[pick[i]]);
  }

  printf("\nEDGE_SEL_REG final      : 0x%08X\n", final_val);

  /* Verification with retries. A single half-second wait is not enough
   * after shaking all four links about: the lock sometimes takes longer,
   * and sometimes the sync has to be repeated. */
  {
    uint32_t wanted = 0;
    int attempt;

    for (i = 0; i < nlinks; i++)
      if (pick[i] >= 0)
        wanted |= 1u << i;

    sta = 0;
    for (attempt = 0; attempt < 6; attempt++) {
      usleep((useconds_t)settle_ms * 1000);
      err = fpga_read(OFF_DM, DM_STATUS_REG, &sta);
      if (err != SAMPA_OK)
        break;
      if ((sta & wanted) == wanted)
        break;
      resync();          /* insist: the chip must re-emit the pattern */
    }

    printf("sincronia tras aplicar  : ");
    for (i = 0; i < nlinks; i++)
      printf("%d", (sta >> i) & 1);
    printf("   (link 0 on the left)");
    if (wanted == 0)
      printf("   (there was no link to lock onto)\n");
    else if (err == SAMPA_OK && (sta & wanted) == wanted)
      printf("   OK tras %d attempt(s)\n", attempt + 1);
    else
      printf("\n  AVISO: esperaba enganchar 0b");
    if (wanted != 0 && !(err == SAMPA_OK && (sta & wanted) == wanted)) {
      for (i = nlinks - 1; i >= 0; i--)
        printf("%d", (wanted >> i) & 1);
      printf(" and 6 attempts were not enough.\n"
             "  Prueba a mano:  sampa_cfg write 0 CMD 6\n");
    }
  }

  if (imposibles) {
    printf("\n%d of %d links did not settle.\n", imposibles, nlinks);
    printf("  \"-\" in all four cells = the link never locks: check the\n");
    printf("  wiring, the termination, or whether the chip really drives it.\n");
    printf("  \"cae xN\" = locks but drops out: that is signal quality.\n");
  } else {
    printf("\nLos %d enlaces quedan estables.\n", buenos);
  }

  return imposibles ? 1 : 0;
}

static int cmd_dump(uint8_t chip)
{
  size_t i;
  int failures = 0;

  printf("%-12s %-5s %-6s  %s\n", "REGISTER", "ADDR", "VALUE", "DESCRIPTION");
  for (i = 0; i < sampa_glb_regs_count; i++) {
    const sampa_reg_t *r = &sampa_glb_regs[i];
    uint8_t v;
    int err = sampa_read_glob(chip, r->addr, &v);

    if (err) {
      printf("%-12s 0x%02X  %-6s  %s\n", r->name, r->addr, "----", sampa_strerror(err));
      failures++;
    } else {
      printf("%-12s 0x%02X  0x%02X    %s%s\n", r->name, r->addr, v,
             r->read_only ? "(read-only) " : "", r->desc);
    }
  }
  return failures ? 1 : 0;
}

static int cmd_dumpch(uint8_t chip, uint8_t ch)
{
  size_t i;
  int failures = 0;

  printf("Channel %u of chip %u\n\n", ch, chip);
  printf("%-12s %-5s %-8s  %s\n", "REGISTER", "ADDR", "VALUE", "DESCRIPTION");
  for (i = 0; i < sampa_ch_regs_count; i++) {
    const sampa_reg_t *r = &sampa_ch_regs[i];
    uint16_t v;
    int err = sampa_read_ch(chip, ch, r->addr, &v);

    if (err) {
      printf("%-12s 0x%02X  %-8s  %s\n", r->name, r->addr, "------", sampa_strerror(err));
      failures++;
    } else {
      printf("%-12s 0x%02X  0x%04X    %s%s\n", r->name, r->addr, v,
             r->read_only ? "(read-only) " : "", r->desc);
    }
  }
  return failures ? 1 : 0;
}

static int cmd_regs(void)
{
  size_t i;

  printf("=== Global registers (%zu) ===\n", sampa_glb_regs_count);
  for (i = 0; i < sampa_glb_regs_count; i++)
    printf("  %-12s 0x%02X  %2d bits  %s%s\n",
           sampa_glb_regs[i].name, sampa_glb_regs[i].addr,
           sampa_glb_regs[i].size,
           sampa_glb_regs[i].read_only ? "(read-only) " : "",
           sampa_glb_regs[i].desc);

  printf("\n=== Channel registers (%zu) ===\n", sampa_ch_regs_count);
  for (i = 0; i < sampa_ch_regs_count; i++)
    printf("  %-12s 0x%02X  %2d bits  %s%s\n",
           sampa_ch_regs[i].name, sampa_ch_regs[i].addr,
           sampa_ch_regs[i].size,
           sampa_ch_regs[i].read_only ? "(read-only) " : "",
           sampa_ch_regs[i].desc);
  return 0;
}

/* Traduce un nombre a direccion; si no existe, avisa y devuelve -1. */
static int resolve(const sampa_reg_t *(*finder)(const char *),
                   const char *name, const sampa_reg_t **out)
{
  const sampa_reg_t *r = finder(name);
  if (!r) {
    fprintf(stderr, "Unknown register '%s'. Try '%s regs'.\n", name, "sampa_cfg");
    return -1;
  }
  *out = r;
  return 0;
}

int main(int argc, char **argv)
{
  const sampa_reg_t *r;
  const char *cmd;
  int err, rc, argi = 1;
  int verify = 0, dry_run = 0;
  uint8_t chip;

  while (argi < argc && argv[argi][0] == '-') {
    if (strcmp(argv[argi], "-v") == 0)             sampa_set_verbose(1);
    else if (strcmp(argv[argi], "--verify") == 0)  verify = 1;
    else if (strcmp(argv[argi], "--dry-run") == 0) dry_run = 1;
    else { fprintf(stderr, "Opcion desconocida: %s\n", argv[argi]); return 2; }
    argi++;
  }
  if (argc <= argi) {
    usage(argv[0]);
    return 2;
  }
  cmd  = argv[argi];
  argc -= argi;
  argv += argi;

  if (strcmp(cmd, "regs") == 0)
    return cmd_regs();

  /* En dry-run no se toca el hardware: no hace falta ni placa ni root. */
  if (strcmp(cmd, "apply") == 0 && dry_run) {
    char errbuf[256];
    if (argc < 2) { usage("sampa_cfg"); return 2; }
    rc = config_apply(argv[1], 0, 1, errbuf, sizeof errbuf);
    if (rc != 0)
      fprintf(stderr, "\n%s\n", errbuf);
    return rc == 0 ? 0 : 1;
  }

  err = sampa_open();
  if (err) {
    fprintf(stderr, "Could not open the bridge: %s\n", sampa_strerror(err));
    return 1;
  }

  chip = (argc > 1) ? (uint8_t)num(argv[1]) : 0;

  if (strcmp(cmd, "fixsync") == 0) {
    rc = cmd_fixsync((argc > 1) ? (unsigned)num(argv[1]) : 1000);

  } else if (strcmp(cmd, "probe") == 0) {
    rc = cmd_probe(chip);

  } else if (strcmp(cmd, "dump") == 0) {
    rc = cmd_dump(chip);

  } else if (strcmp(cmd, "dumpch") == 0 && argc >= 3) {
    rc = cmd_dumpch(chip, (uint8_t)num(argv[2]));

  } else if (strcmp(cmd, "read") == 0 && argc >= 3) {
    uint8_t v;
    rc = resolve(sampa_find_glb, argv[2], &r);
    if (rc == 0) {
      err = sampa_read_glob(chip, r->addr, &v);
      if (err) { fprintf(stderr, "%s\n", sampa_strerror(err)); rc = 1; }
      else     { printf("%s = 0x%02X (%u)\n", r->name, v, v); }
    }

  } else if (strcmp(cmd, "write") == 0 && argc >= 4) {
    rc = resolve(sampa_find_glb, argv[2], &r);
    if (rc == 0) {
      if (r->read_only) {
        fprintf(stderr, "%s is read-only.\n", r->name);
        rc = 1;
      } else {
        uint8_t val = (uint8_t)num(argv[3]);
        err = sampa_write_glob(chip, r->addr, val);
        /* A soft reset (CMD = 5) restarts the chip DURING the I2C
         * transaction itself, so it never gets to raise the ACK. The NACK
         * is expected and the command does run: it is not a hardware
         * failure. */
        if (err == SAMPA_ERR_NACK && r->addr == SMP_CMD && val == 5) {
          printf("%s <- 0x%02X   (no ACK: the soft reset cuts the I2C\n"
                 "            transaction itself; this is normal)\n",
                 r->name, (unsigned)val);
        } else if (err) {
          fprintf(stderr, "%s\n", sampa_strerror(err));
          rc = 1;
        } else {
          printf("%s <- 0x%02X\n", r->name, (unsigned)val);
        }
      }
    }

  } else if (strcmp(cmd, "readch") == 0 && argc >= 4) {
    uint16_t v;
    rc = resolve(sampa_find_ch, argv[3], &r);
    if (rc == 0) {
      err = sampa_read_ch(chip, (uint8_t)num(argv[2]), r->addr, &v);
      if (err) { fprintf(stderr, "%s\n", sampa_strerror(err)); rc = 1; }
      else     { printf("%s = 0x%04X (%u)\n", r->name, v, v); }
    }

  } else if (strcmp(cmd, "writech") == 0 && argc >= 5) {
    int bcast = (strcmp(argv[2], "all") == 0);
    uint8_t ch = bcast ? 0 : (uint8_t)num(argv[2]);
    rc = resolve(sampa_find_ch, argv[3], &r);
    if (rc == 0) {
      if (r->read_only) {
        fprintf(stderr, "%s is read-only.\n", r->name);
        rc = 1;
      } else {
        err = sampa_write_ch(chip, ch, bcast, r->addr, (uint16_t)num(argv[4]));
        if (err) { fprintf(stderr, "%s\n", sampa_strerror(err)); rc = 1; }
        else     { printf("%s <- 0x%04X (%s)\n", r->name, (unsigned)num(argv[4]),
                          bcast ? "all channels" : "one channel"); }
      }
    }

  } else if (strcmp(cmd, "apply") == 0 && argc >= 2) {
    char errbuf[256];
    rc = config_apply(argv[1], verify, dry_run, errbuf, sizeof errbuf);
    if (rc > 0)       { fprintf(stderr, "\n%d error(s). The first one: %s\n", rc, errbuf); rc = 1; }
    else if (rc < 0)  { fprintf(stderr, "\n%s\n", errbuf); rc = 1; }
    else              { printf("\nConfiguration applied with no errors.\n"); }

  } else {
    usage("sampa_cfg");
    rc = 2;
  }

  sampa_close();
  return rc;
}
