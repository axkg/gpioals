[comment]: # (SPDX-License-Identifier: GPL-2.0)
[comment]: # (SPDX-FileCopyrightText: © 2023 Alexander König <alex@lisas.de>)

# GPIO Ambient Light Sensor

This module for the Linux kernel allows measuring ambient light intensity with
just a light dependent resistor (LDR) and a capacitor.

The following schematic shows how the LDR (L) and the capacitor (C) are
connected to the Pi:

```
  +--------------+
  | Raspberry Pi |
  |              |
  |          +-+ |
  |          |G| |   +-+
  |    POWER---------|L|--+
  |          |P| |   +-+  |
  |     GPIO--------------+
  |          |I| |   | |  |
  |      GND---------|C|--+
  |          |O| |   | |
  |          +-+ |
  +--------------+
```

Even though I cannot find the original instructions I followed, there are a
couple of similar ones available, e.g [this one from Robo
India](https://roboindia.com/tutorials/raspberry-ldr/). The software solution
commonly proposed to measure the light the LDR is exposed to, is to poll the
GPIO pin to detect when the capacitor is charged. The drawback here is not only
the fact that this approach keeps the CPU busy during the measurement and
context switches as well as getting the information from/to user space introduce
a lot of noise.

In order to address both of these issues, this kernel module detects the charged
capacitor through an interrupt and measures all timestamps directly in kernel
space to reduce the jitter. Note that
[gpiod](https://git.kernel.org/pub/scm/libs/libgpiod/libgpiod.git/) addresses
the second part (timestamping the interrupt) but not the timestamping of
switching the GPIO port direction.

## Building the module

Building the kernel module should be straight forward: Install the headers that
match the kernel currently running on the Raspberry Pi (on Raspbian installing
the matching `raspberrypi-kernel-headers` should be sufficient) and run `make`.

## Loading the module

The GPIO pin to be used can be configured via the module parameter
`gpioals_gpio_pin`, by default pin `10` will be used.

## Userspace interface

When the module is loaded, udev should automatically create a `/dev/gpioals`
character device. Currently only one process is allowed to open the device.

### Writing to the device

A user space process needs to open the device with read and write access, as
currently gpioals expects user space to trigger measurements. Commands are sent
as single byte writes to the device. The following commands are currently
supported:

| Byte | Command    | Details                                                                                    |
|------|------------|--------------------------------------------------------------------------------------------|
| 0    | CANCEL     | Cancel any running measurements                                                            |
| 1    | ARM        | Set the GPIO pin to low to discharge the capacitor                                         |
| 2    | MEASURE    | Switch the GPIO port back to input and wait for the interrupt and complete the measurement |
| 3    | STATISTICS | Will trigger the module to `printk()` some internal counters for debugging                 |

### Reading events from the device

The device will allow reading multiples of 16 bytes only. 16 bytes is the
minimum as single measurement holds two 64bit integers:

| Bits   | Value                                                                        |
|--------|------------------------------------------------------------------------------|
|  0-63  | `ktime_t` timestamp when the measurement was taken                           |
| 64-127 | Time delta in nanoseconds from the flipping of the GPIO pin to the interrupt | 

## Interpreting the measurements

The shorter the measured time delta is, the more light should have been detected
by the LDR. The actual timing depends on the actual LDR and capacitator used. If
the environment is too dark, the interrupt will not trigger within the
observation time, alas no measurement will be available. So if userspace is
triggering measurements but not reading any measurements, one should assume that
it is too dark for the "sensor" to measure.
