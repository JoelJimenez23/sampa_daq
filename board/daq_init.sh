#!/bin/sh
#
# daq_init.sh - leave the board ready to acquire, with nothing to click.
#
# What the Windows GUI used to do by hand over the UART: enable the serial
# links that are in sync, arm the acquisition and send the bunch-crossing
# sync. Meant to be called from /etc/init.d/sampa, AFTER sampa_server has
# started.
#
# On synchronisation: there is nothing to "tune". If the links do not lock
# at boot, what is needed is a power cycle of the board, not fiddling with
# sampling edges. This script checks that and says so, instead of leaving
# the system half-started in silence.

DAQSTAT=${DAQSTAT:-/usr/bin/daqstat}
PACKETS=${PACKETS:-2048}
WAIT=${WAIT:-15}          # seconds we give the links to lock

log() { echo "daq_init: $*"; }

[ -x "$DAQSTAT" ] || { log "cannot find $DAQSTAT"; exit 1; }

# 1. Wait for the links to lock. After a cold start they take a while.
i=0
while [ "$i" -lt "$WAIT" ]; do
  if "$DAQSTAT" 0xFF201068 1 2>/dev/null | grep -qv ' 0x00000000 '; then
    break
  fi
  i=$((i + 1))
  sleep 1
done

# 2. Enable exactly the ones that are in sync.
if ! "$DAQSTAT" links auto; then
  log "NO link in sync after ${WAIT}s."
  log "That is not fixable in software: power-cycle the board."
  exit 1
fi

# 3. Arm and synchronise.
"$DAQSTAT" acquire "$PACKETS" || exit 1
"$DAQSTAT" bxsync              || exit 1

log "ready. Connect a client to port 1000 and trigger with:"
log "  $DAQSTAT trigger"
