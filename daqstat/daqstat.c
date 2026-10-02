/*
 * daqstat - read (and write) the DAQ registers inside the FPGA from the
 * Linux running on the HPS.
 *
 *   daqstat                  dump the DAQ state, already interpreted
 *   daqstat 0xFF20003C       read a single address (like devmem)
 *   daqstat 0xFF201000 16    read 16 consecutive words
 *   daqstat -w ADDR VAL      write one word
 *
 * plus a few named commands that mirror the "Run Control" tab of the
 * Windows GUI:
 *
 *   daqstat links MASK       enable serial links (bits 0..10) and DAS (bit 11)
 *   daqstat links auto       enable whichever links are in sync right now
 *   daqstat acquire [N]      start acquisition of N packets (default 2048)
 *   daqstat trigger          send an event trigger to the SAMPA
 *   daqstat bxsync           send the bunch-crossing sync
 *   daqstat fifoclear        clear the FIFO-full sticky flag
 *   daqstat fakeclient on    fake a TCP client (bit 0 of the HPS register)
 *
 * This exists because this BusyBox has no devmem applet, and because knowing
 * whether the serial links are in sync says far more than a bare number.
 *
 * If the FPGA is not configured, or the lwhps2fpga bridge is disabled,
 * reading these addresses raises SIGBUS. Instead of dying with a bare
 * "Bus error" we catch it and spell it out, because that failure IS the
 * diagnosis.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>

#define LW_BASE   0xFF200000u
#define LW_SPAN   0x00004000u

#define OFF_CNC   0x0000u
#define OFF_DM    0x1000u

/* word offsets inside each block (see Form1.cs) */
#define CNC_CMD       3
#define CNC_PULSE     4
#define CNC_EVTCFG    7
#define CNC_SMPCFG   12
#define CNC_VER      15
#define DM_CNTRL     0x00
#define DM_PKT0      0x01
#define DM_PKTDAS    0x0C
#define DM_FIFO0     0x0D
#define DM_HPS       0x19
#define DM_STATUS    0x1A
#define DM_SYNC0     0x1B
#define DM_DROP0     0x27
#define DM_TRUNC0    0x33

#define NUM_LINKS    11

/* CNTRL_REG bits (DM word 0) */
#define CNTRL_DAS     (1u << 11)   /* enable the path to the DDR3    */
#define CNTRL_START   (1u << 12)   /* pulse: start acquisition        */
#define CNTRL_FIFOCLR (1u << 13)   /* pulse: clear FIFO-full flag     */

/* CMD_REG commands (CNC word 3), field [15:0] */
#define CMD_RESET_ALL   1
#define CMD_RESET_SAMPA 2
#define CMD_EVT_TRG     3
#define CMD_HB_TRG      4
#define CMD_BX_SYNC     5

/* SMP_CFG_REG bit 20: re-syncs the DAS by pulsing it 0 -> 1 */
#define SMPCFG_DAS_SYNC (1u << 20)

static sigjmp_buf busjmp;
static volatile sig_atomic_t bus_hit;

static void on_bus(int sig)
{
  (void)sig;
  bus_hit = 1;
  siglongjmp(busjmp, 1);
}

static volatile uint32_t *lw;

/* Guarded read: returns 0 and sets *ok to 0 if the bus complains. */
static uint32_t rd(unsigned byte_off, int *ok)
{
  uint32_t v;

  bus_hit = 0;
  if (sigsetjmp(busjmp, 1) != 0) {
    *ok = 0;
    return 0;
  }
  v = lw[byte_off / 4];
  *ok = 1;
  return v;
}

/* Guarded write: returns 0 if the bus complains. */
static int wr(unsigned byte_off, uint32_t val)
{
  bus_hit = 0;
  if (sigsetjmp(busjmp, 1) != 0)
    return 0;
  lw[byte_off / 4] = val;
  return 1;
}

static void bus_dead(void)
{
  printf("\n  BUS ERROR while talking to the FPGA.\n\n");
  printf("  The bridge is there (the mmap worked) but nobody answers on the\n");
  printf("  other side. The two possible causes:\n\n");
  printf("    - the FPGA is not configured (the .rbf was never loaded)\n");
  printf("    - the lwhps2fpga bridge is disabled\n");
}

/* Read-modify-write of a field, like cnc_write_single_pos in the GUI. */
static int poke_field(unsigned byte_off, int pos, uint32_t mask, uint32_t val)
{
  int ok;
  uint32_t cur = rd(byte_off, &ok);

  if (!ok)
    return 0;
  cur = (cur & ~(mask << pos)) | ((val & mask) << pos);
  return wr(byte_off, cur);
}

static void dump_status(void)
{
  int ok;
  uint32_t ver, hps, sta, ctl, cmd, evt, smp, pul;
  int i;

  ver = rd(OFF_CNC + CNC_VER * 4, &ok);
  if (!ok) {
    bus_dead();
    return;
  }

  printf("--- FPGA ------------------------------------------------\n");
  printf("  firmware version     : %u", ver);
  if (ver == 0 || ver == 0xFFFFFFFFu)
    printf("   <-- SUSPICIOUS: the FPGA does not look configured");
  else if (ver < 700)
    printf("   <-- old firmware (>= 700 expected)");
  printf("\n");

  hps = rd(OFF_DM + DM_HPS * 4, &ok);
  sta = rd(OFF_DM + DM_STATUS * 4, &ok);
  ctl = rd(OFF_DM + DM_CNTRL * 4, &ok);
  cmd = rd(OFF_CNC + CNC_CMD * 4, &ok);
  evt = rd(OFF_CNC + CNC_EVTCFG * 4, &ok);
  smp = rd(OFF_CNC + CNC_SMPCFG * 4, &ok);
  pul = rd(OFF_CNC + CNC_PULSE * 4, &ok);

  printf("\n--- sampa_server ----------------------------------------\n");
  printf("  HPS register         : 0x%08X\n", hps);
  printf("  server version       : %u\n", hps >> 8);
  printf("  client connected     : %s\n", (hps & 1) ? "YES" : "NO");
  if (!(hps & 1))
    printf("      (with no client the FPGA pushes no data: by design)\n");

  printf("\n--- acquisition ------------------------------------------\n");
  printf("  CNTRL_REG            : 0x%08X\n", ctl);
  printf("  DAS path (DDR3)      : %s\n", (ctl & CNTRL_DAS) ? "enabled" : "OFF");
  /* The field counts packets PER LINK. Since each link carries 8 channels,
   * one readout of all 32 costs 8 packets: hence the /8. */
  printf("  packets to acquire   : %u per link", ctl >> 16);
  /* Zero is NOT "nothing": p_pkt_cntr in data_manager.vhd sets the target to
   * 0xFFFFFFFF when acq_len is 0, which is 2^32 packets per link, about 15
   * hours. It is the firmware's continuous mode. The register alone cannot
   * say whether a burst was ever started, so word it carefully. */
  if ((ctl >> 16) == 0)
    printf("   <-- 0 = unlimited (continuous) once a burst is started\n");
  else
    printf("  (%u readouts, %.1f ms)\n", (ctl >> 16) / 8u,
           (ctl >> 16) * 0.0125);
  printf("  CMD_REG              : 0x%08X   (pulses=%u  continuous=%u)\n",
         cmd, (cmd >> 16) & 0x7FFF, (cmd >> 31) & 1);
  printf("  PULSE_REG            : 0x%08X\n", pul);
  printf("  EVT_CFG_REG          : 0x%08X\n", evt);
  printf("  SMP_CFG_REG          : 0x%08X\n", smp);

  printf("\n--- serial links -----------------------------------------\n");
  printf("  STATUS_REG           : 0x%08X\n", sta);
  printf("\n");
  printf("   link  enabled  sync  fifo-full    packets  sync-loss  dropped  trunc\n");
  for (i = 0; i < NUM_LINKS; i++) {
    printf("   %-4d  %-7s  %-4s  %-9s %10u %10u %8u %6u\n", i,
           ((ctl >> i) & 1) ? "yes" : "NO",
           ((sta >> i) & 1) ? "yes" : "NO",
           ((sta >> (12 + i)) & 1) ? "YES" : "no",
           rd(OFF_DM + (DM_PKT0 + i) * 4, &ok),
           rd(OFF_DM + (DM_SYNC0 + i) * 4, &ok),
           rd(OFF_DM + (DM_DROP0 + i) * 4, &ok),
           rd(OFF_DM + (DM_TRUNC0 + i) * 4, &ok));
  }
  printf("   DAS   %-7s  %-4s  %-9s %10u %10s %8u %6u\n",
         (ctl & CNTRL_DAS) ? "yes" : "NO",
         ((sta >> 11) & 1) ? "yes" : "NO",
         ((sta >> 23) & 1) ? "YES" : "no",
         rd(OFF_DM + DM_PKTDAS * 4, &ok),
         "-",          /* the DAS path has no sync-loss counter */
         rd(OFF_DM + (DM_DROP0 + NUM_LINKS) * 4, &ok),
         rd(OFF_DM + (DM_TRUNC0 + NUM_LINKS) * 4, &ok));

  printf("\n--- what to look at --------------------------------------\n");
  if ((sta & 0xFFF) == 0) {
    printf("  NO link is in sync. Not a single packet will ever arrive this\n"
           "  way. Check the SAMPA clock, the DM serial links, and whether\n"
           "  the configuration was ever applied.\n");
  } else if ((ctl & (sta & 0x7FF)) == 0) {
    printf("  Some links are in sync but NONE is enabled in CNTRL_REG.\n"
           "  Enable them:  daqstat links 0x%03X\n",
           (unsigned)(sta & 0x7FFu));
  } else if ((ctl & CNTRL_DAS) && (ctl & 0x7FFu)) {
    printf("  DAS and serial links enabled at once: they are EXCLUSIVE.\n"
           "  Keep the serial links:  daqstat links 0x%03X\n",
           (unsigned)(ctl & 0x7FFu));
  } else if (!(hps & 1)) {
    printf("  The FPGA is ready, but there is no client on port 1000 and\n"
           "  without one nothing is pushed. Connect the sniffer, or to\n"
           "  exercise the FPGA alone:  daqstat fakeclient on\n");
  } else if ((ctl >> 16) == 0) {
    printf("  The acquire count is 0, which the firmware reads as UNLIMITED.\n"
           "  If no packet is arriving, the burst was never started:\n"
           "      daqstat acquire 0       <- continuous, until stopped\n"
           "      daqstat acquire 2048    <- one burst of 25.6 ms\n");
  } else {
    printf("  Links enabled and in sync. If the packet counters do not\n"
           "  rise, you still need to start and trigger:\n"
           "      daqstat acquire 2048\n"
           "      daqstat bxsync\n"
           "      daqstat trigger\n");
  }
}

/* Mirrors acquire_Click from the GUI. */
static int do_acquire(unsigned long n)
{
  int ok;
  uint32_t ctl, smp;

  ctl = rd(OFF_DM + DM_CNTRL * 4, &ok);
  if (!ok)
    return 0;
  smp = rd(OFF_CNC + CNC_SMPCFG * 4, &ok);
  if (!ok)
    return 0;

  /* With DAS enabled the GUI pulses it 0 -> 1 around the start to re-sync
   * it; otherwise it ends up out of step with the first packet. */
  if (ctl & CNTRL_DAS)
    if (!wr(OFF_CNC + CNC_SMPCFG * 4, smp & ~SMPCFG_DAS_SYNC))
      return 0;

  ctl = (ctl & 0x0000FFFFu) | ((uint32_t)n << 16);
  if (!wr(OFF_DM + DM_CNTRL * 4, ctl | CNTRL_START))
    return 0;

  if (ctl & CNTRL_DAS)
    if (!wr(OFF_CNC + CNC_SMPCFG * 4, smp | SMPCFG_DAS_SYNC))
      return 0;

  printf("acquisition started (packets: %lu)\n", n);
  if (n == 0)
    printf("  CONTINUOUS: the firmware takes 0 as 2^32 packets per link,\n"
           "  about 15 hours. It does not stop by itself; to stop it, start\n"
           "  a finite burst (daqstat acquire 1) and let it finish.\n");
  return 1;
}

static void usage(void)
{
  fprintf(stderr,
    "usage:\n"
    "  daqstat                  interpreted DAQ status\n"
    "  daqstat ADDR [N]         read N words starting at ADDR\n"
    "  daqstat -w ADDR VAL      write one word\n"
    "  daqstat links MASK       enable links (bits 0..10) and DAS (bit 11)\n"
    "  daqstat links auto       enable whichever links are in sync now\n"
    "  daqstat acquire [N]      start a burst of N packets PER LINK\n"
    "                           (default 2048). Each link carries 8 channels,\n"
    "                           so that is N/8 readouts, i.e. N*12.5 us.\n"
    "                           The burst ends by itself: to continue, acquire again\n"
    "  daqstat acquire 0        CONTINUOUS: 0 means unlimited to the firmware\n"
    "  daqstat trigger          event trigger\n"
    "  daqstat bxsync           bunch-crossing sync\n"
    "  daqstat fifoclear        clear the FIFO-full flag\n"
    "  daqstat fakeclient on    fake a TCP client (debugging only)\n");
}

int main(int argc, char **argv)
{
  int fd, ok, rc = 0;
  void *p;
  unsigned long addr;
  unsigned count = 1, i;

  signal(SIGBUS, on_bus);
  signal(SIGSEGV, on_bus);

  if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
    usage();
    return 0;
  }

  fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (fd < 0) {
    perror("could not open /dev/mem (root required)");
    return 1;
  }
  p = mmap(NULL, LW_SPAN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, LW_BASE);
  if (p == MAP_FAILED) {
    perror("mmap of the bridge failed");
    close(fd);
    return 1;
  }
  lw = (volatile uint32_t *)p;

  if (argc == 1) {
    dump_status();
    goto out;
  }

  if (strcmp(argv[1], "links") == 0) {
    uint32_t mask;
    if (argc < 3) {
      usage();
      rc = 2;
      goto out;
    }
    if (strcmp(argv[2], "auto") == 0) {
      /* Enable exactly the links that are in sync right now, so startup
       * does not depend on a hand-written mask that may be wrong
       * tomorrow. */
      uint32_t sta = rd(OFF_DM + DM_STATUS * 4, &ok);
      if (!ok) {
        bus_dead();
        rc = 1;
        goto out;
      }
      mask = sta & 0x7FFu;
      if (mask == 0) {
        printf("no link is in sync: there is nothing to enable\n");
        rc = 1;
        goto out;
      }
      printf("links in sync: 0x%03X\n", mask);
    } else {
      /* Without checking the end pointer, strtoul("auto") returns 0 and we
       * would end up DISABLING every link instead of enabling them, without
       * saying a word. That happened for real with an older daqstat that
       * lacked the "auto" branch above. Better to refuse than to switch
       * everything off by surprise. */
      char *end = NULL;
      unsigned long v = strtoul(argv[2], &end, 0);
      if (end == argv[2] || *end != '\0') {
        fprintf(stderr, "cannot parse the mask \"%s\": give a number "
                        "(0x00F) or the word auto\n", argv[2]);
        rc = 2;
        goto out;
      }
      mask = (uint32_t)v & 0xFFFu;
      if (mask == 0)
        printf("warning: mask 0, this DISABLES every link\n");
    }
    /* DAS and the serial links are MUTUALLY EXCLUSIVE paths: in the GUI,
     * ticking DAS unticks all eleven links and vice versa
     * (enReadouts_Click). Enabling both at once is not a valid setup. */
    if (mask & CNTRL_DAS) {
      if (mask & 0x7FFu)
        printf("warning: DAS and serial links are exclusive; keeping DAS\n");
      mask = CNTRL_DAS;
    } else {
      /* Leaving DAS mode requires dropping its trg and sync lines. */
      if (!poke_field(OFF_CNC + CNC_SMPCFG * 4, 19, 0x3u, 0)) {
        bus_dead();
        rc = 1;
        goto out;
      }
    }
    ok = poke_field(OFF_DM + DM_CNTRL * 4, 0, 0xFFFu, mask);
    if (ok)
      printf("CNTRL_REG = 0x%08X\n", rd(OFF_DM + DM_CNTRL * 4, &ok));
    else
      bus_dead();
    rc = ok ? 0 : 1;
    goto out;
  }

  if (strcmp(argv[1], "acquire") == 0) {
    unsigned long n = (argc > 2) ? strtoul(argv[2], NULL, 0) : 2048;
    if (!do_acquire(n)) {
      bus_dead();
      rc = 1;
    }
    goto out;
  }

  if (strcmp(argv[1], "trigger") == 0 || strcmp(argv[1], "bxsync") == 0 ||
      strcmp(argv[1], "reset") == 0) {
    uint32_t c = (strcmp(argv[1], "trigger") == 0) ? CMD_EVT_TRG :
                 (strcmp(argv[1], "bxsync")  == 0) ? CMD_BX_SYNC :
                                                     CMD_RESET_SAMPA;
    if (poke_field(OFF_CNC + CNC_CMD * 4, 0, 0xFFFFu, c))
      printf("command %s sent (CMD_REG[15:0] = %u)\n", argv[1], c);
    else {
      bus_dead();
      rc = 1;
    }
    goto out;
  }

  if (strcmp(argv[1], "fakeclient") == 0) {
    uint32_t on = (argc > 2 && strcmp(argv[2], "off") == 0) ? 0 : 1;
    /* Same as the "fake client" checkbox on the GUI's Debug tab.
     * sampa_server overwrites this bit when it accepts or closes a
     * connection, so it is only useful to exercise the FPGA -> DDR3 path
     * with no TCP client attached. */
    if (poke_field(OFF_DM + DM_HPS * 4, 0, 0x1u, on))
      printf("fake client: %s\n", on ? "ON" : "OFF");
    else {
      bus_dead();
      rc = 1;
    }
    goto out;
  }

  if (strcmp(argv[1], "fifoclear") == 0) {
    if (poke_field(OFF_DM + DM_CNTRL * 4, 13, 0x1u, 1))
      printf("FIFO-full flag cleared\n");
    else {
      bus_dead();
      rc = 1;
    }
    goto out;
  }

  if (strcmp(argv[1], "-w") == 0) {
    if (argc < 4) {
      usage();
      rc = 2;
      goto out;
    }
    addr = strtoul(argv[2], NULL, 0);
    if (addr < LW_BASE || addr + 4 > LW_BASE + LW_SPAN) {
      fprintf(stderr, "address outside the bridge (0x%08X..0x%08X)\n",
              LW_BASE, LW_BASE + LW_SPAN - 1);
      rc = 2;
      goto out;
    }
    if (wr((unsigned)(addr - LW_BASE), (uint32_t)strtoul(argv[3], NULL, 0)))
      printf("0x%08lX  <- 0x%08lX\n", addr, strtoul(argv[3], NULL, 0));
    else {
      bus_dead();
      rc = 1;
    }
    goto out;
  }

  /* Whatever is left must be an address. Without checking the end pointer,
   * strtoul("aquire") returns 0 and we would read address 0 and complain it
   * is "outside the bridge", which helps nobody who simply dropped a letter
   * while typing. That happened for real. */
  {
    char *end = NULL;
    addr = strtoul(argv[1], &end, 0);
    if (end == argv[1] || *end != '\0') {
      fprintf(stderr, "unknown command \"%s\".\n\n", argv[1]);
      usage();
      rc = 2;
      goto out;
    }
  }
  if (argc > 2)
    count = (unsigned)strtoul(argv[2], NULL, 0);

  if (addr < LW_BASE || addr + count * 4 > LW_BASE + LW_SPAN) {
    fprintf(stderr, "address outside the bridge (0x%08X..0x%08X)\n",
            LW_BASE, LW_BASE + LW_SPAN - 1);
    rc = 2;
    goto out;
  }

  for (i = 0; i < count; i++) {
    unsigned off = (unsigned)(addr - LW_BASE) + i * 4;
    uint32_t v = rd(off, &ok);
    if (!ok) {
      bus_dead();
      rc = 1;
      goto out;
    }
    printf("0x%08lX  0x%08X  %u\n", addr + i * 4, v, v);
  }

out:
  munmap(p, LW_SPAN);
  close(fd);
  return rc;
}
