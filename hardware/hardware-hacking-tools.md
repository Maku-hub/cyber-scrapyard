# Hardware Hacking Tools

> Bench gear for talking to the low-level buses inside embedded devices — UART,
> JTAG/SWD, SPI, and I²C — to dump firmware, get a root shell, and reverse
> unknown boards.

- **Link:** https://github.com/DangerousPrototypes/BusPirate5
- **Type:** open hardware / open source
- **Platform:** cross-platform (sigrok/PulseView, `flashrom`, `OpenOCD`, serial terminals)

## Description

Once you crack open a router, IoT gadget, or industrial box, the interesting
attack surface is on the PCB: debug headers, flash chips, and test pads. These
tools let you speak the on-board protocols directly — sniff a serial console to
watch a device boot, brute-force which pins are a JTAG port, decode an SPI bus
with a logic analyzer, or clip onto a flash chip and read the firmware straight
off it. They turn an opaque black box into something you can enumerate, dump,
and modify.

## Devices worth knowing

| Device | What it does | Role |
| --- | --- | --- |
| **Bus Pirate** | Open-source multi-tool that speaks UART, SPI, I²C, 1-Wire, JTAG and more from a serial prompt | Universal "talk to any bus" probe |
| **JTAGulator** | Automatically identifies JTAG/UART pinouts on unknown headers by brute-forcing the pins | Finds debug ports so you don't have to guess |
| **Logic analyzer (sigrok)** | Multi-channel digital capture; sigrok/PulseView decodes the captured lines into protocols | Passive bus sniffing and protocol decoding |
| **SPI flash clip + programmer** | Pomona-style clip onto an SOIC flash chip, read/write with `flashrom` | Dumping and reflashing firmware |

## Usage examples

```bash
# Read a serial console (UART) from a device's debug header at a common baud rate
screen /dev/ttyUSB0 115200

# List logic analyzer drivers/devices sigrok can see
sigrok-cli --list-supported | grep -i driver

# Capture 4 channels at 1 MHz for 1 second and save for PulseView
sigrok-cli -d fx2lafw --channels D0,D1,D2,D3 --config samplerate=1m --time 1s -o capture.sr

# Decode captured lines as UART right from the CLI
sigrok-cli -i capture.sr -P uart:rx=D0:baudrate=115200

# Identify the flash chip on an SPI programmer, then dump it
flashrom -p ch341a_spi
flashrom -p ch341a_spi -r firmware_dump.bin
```

## Notes & references

- **Bus Pirate** (Dangerous Prototypes) — the v5/v6 hardware and firmware:
  https://github.com/DangerousPrototypes/BusPirate5 ; project hub:
  https://buspirate.com
- **JTAGulator** (Grand Idea Studio, by Joe Grand) — hardware and firmware for
  discovering unknown JTAG/UART pinouts:
  https://github.com/grandideastudio/jtagulator
- **sigrok / PulseView** is the open-source signal-analysis suite; cheap
  FX2-based (`fx2lafw`) 8-channel analyzers are the usual budget entry point:
  https://sigrok.org
- **OpenOCD** (https://openocd.org) drives JTAG/SWD adapters for on-chip
  debugging and flash programming once you've found the port.
- **flashrom** (https://www.flashrom.org) reads/writes SPI/parallel flash chips
  via cheap CH341A programmers or the Bus Pirate itself.
- For power-analysis and glitching attacks on chips, step up to the
  [ChipWhisperer](multitools.md).
- ⚠️ Voltage matters — mixing 5 V and 3.3 V logic can destroy a target. Check
  levels before connecting, and only probe hardware you own or are authorized
  to test.
