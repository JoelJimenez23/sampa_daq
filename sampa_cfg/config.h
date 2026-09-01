/*
 * config.h - Apply a TOML configuration file to the hardware.
 */
#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>

/*
 * Reads 'path' and applies it.
 *
 *   verify   != 0 : read each global register back after writing it
 *   dry_run  != 0 : only print what it would do, touch no hardware
 *                   (needs neither the board nor root)
 *
 * Returns the number of errors (0 = all good), or -1 if the file could not
 * be opened or has syntax errors. In that case errbuf explains what happened.
 */
int config_apply(const char *path, int verify, int dry_run,
                 char *errbuf, size_t errsz);

#endif /* CONFIG_H */
