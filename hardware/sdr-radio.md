# SDR & Radio (Software-Defined Radio)

> Radios whose signal processing happens in software instead of fixed hardware,
> so one device can receive (and sometimes transmit) across a huge slice of the
> RF spectrum — the gateway to wireless, IoT, and RF security research.

- **Link:** https://www.rtl-sdr.com
- **Type:** ranges from budget open hardware to commercial
- **Platform:** cross-platform (GNU Radio, SDR#, GQRX, CubicSDR, SDRangel)

## Description

A software-defined radio digitizes raw RF and hands it to software, where you
decode, demodulate, and analyze it. That flexibility lets one dongle listen to
ADS-B aircraft, pagers, trunked radio, weather satellites, or ISM-band devices,
and higher-end units can *transmit* to test and replay signals. It's the
foundation for studying key fobs, garage doors, sensors, GPS, and any wireless
protocol you can tune to. Start cheap (receive-only) to learn, then move up as
your needs grow.

## Devices worth knowing

| Device | Range / capability | Role |
| --- | --- | --- |
| **RTL-SDR V4** | ~500 kHz–1.75 GHz, RX only | Budget entry point; ideal for learning SDR fundamentals |
| **HackRF One** | 1 MHz–6 GHz, **half-duplex TX + RX** | Mid-range workhorse for wireless security research and replay |
| **KrakenSDR** | 5× coherent RTL-SDR channels | Advanced RF analysis and **direction finding** (locating a transmitter) |

## Usage examples

```bash
# Verify an RTL-SDR is detected and read its tuner/EEPROM info
rtl_test -t

# Capture raw samples to a file at a given center frequency and sample rate
rtl_sdr -f 433920000 -s 2048000 -n 8192000 capture.iq

# HackRF: quick spectrum sweep across a range (MHz)
hackrf_sweep -f 400:500
```

## Notes & references

- **RTL-SDR** started as repurposed DVB-T TV tuners; the V3/V4 from the
  rtl-sdr.com blog team are the reference budget dongles. Blog & guides:
  https://www.rtl-sdr.com
- **HackRF One** is made by Great Scott Gadgets:
  https://greatscottgadgets.com/hackrf/ — it's half-duplex (transmit or
  receive, not both at once).
- **KrakenSDR:** https://www.krakenrf.com — five phase-coherent channels enable
  passive radar and direction finding.
- **Airspy** is another popular high-dynamic-range RX line:
  https://airspy.com
- Transmitting is **legally restricted** — most bands require a license. Keep TX
  experiments in a shielded/lab setting or on bands you're licensed for.
- The general-purpose [Flipper Zero](multitools.md) covers sub-GHz replay for
  simpler fobs without a full SDR stack.
