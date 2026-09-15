# Absolute Mouse Detection

I'll make this readme official and pretty later. Just storing my two main scripts for the time being for sharing. Will likely create full repo detailing all PiKVM research.
* hid_axis_mode.ps1 - Analyze all connected pointer devices and determine if it is using absolute or relative mode. Basis for PiKVM research.
* hid_axis_mode.py - same thing, but python version designed for Cortex XDR Agent Scripts. Can still be ran wherever though.

Both scripts check HID collections two ways and merges them by device instance:
*  GetRawInputDeviceList (user32) - per terminal-services session, so it is
        empty or short outside the interactive session, but it authoritatively
        marks a collection as mouse-class.
* CM_Get_Device_Interface_ListW (cfgmgr32) - every present
        GUID_DEVINTERFACE_HID interface, from the PnP manager, with no session
        affinity.

When running automated scripts remotely through a RMM/EDR service, they tend to run as SYSTEM, which cannot see GetRawInputDeviceList.
The second collection method allows you to investigate a machine directly or remotely.  

Will include more detailed explanation page down the road. 
