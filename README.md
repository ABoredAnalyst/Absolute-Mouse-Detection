# Absolute Mouse Detection

I'll make this readme official and pretty later. Just storing my two main scripts for the time being for sharing. Will likely create full repo detailing all PiKVM research.
* hid_axis_mode.ps1 - Analyze all connected pointer devices and determine if it is using absolute or relative mode. Basis for PiKVM research.
* monitor_EDID_duplicate.ps1 - Analyze registered displays and looks for indicators of a cloned display.

Both scripts include a Powershell and Python version. Function exactly the same, but Cortex XDR can only run python format while the main detection logic is done in powershell.

hid_axis_mode checks HID collections two ways and merges them by device instance:
*  GetRawInputDeviceList (user32) - per terminal-services session, so it is
        empty or short outside the interactive session, but it authoritatively
        marks a collection as mouse-class.
* CM_Get_Device_Interface_ListW (cfgmgr32) - every present
        GUID_DEVINTERFACE_HID interface, from the PnP manager, with no session
        affinity.

When running automated scripts remotely through a RMM/EDR service, they tend to run as SYSTEM, which cannot see GetRawInputDeviceList.
The second collection method allows you to investigate a machine directly or remotely.  

Will make this more formal and detailed down the road
