# PiKVM-Detection

I'll make this readme official and pretty later. Just storing my two main scripts for the time being.
* hid_axis_mode.ps1 - Analyze all connected pointer devices and determine if it is using absolute or relative mode. Basis for PiKVM research.
* hid_axis_mode.py - same thing, but python version meant to run via an EDR service (namely Cortex XDR) that runs scripts at SYSTEM level, which cannot effectively see the connected devices.
