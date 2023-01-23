May need VirtualBox 6.1.30. At the time I had 6.1.34 and it wasn't working, but I think it might've been caused by the USB thingy that's now fixed in the Vagrantfile.

This may or may not be needed, keeping here for reference:
```shell
cd "C:\Program Files\Oracle\VirtualBox\"
VBoxManage.exe modifyvm "getmac-osx-mojave" --cpuidset 00000001 000106e5 00100800 0098e3fd bfebfbff
VBoxManage setextradata "getmac-osx-mojave" "VBoxInternal/Devices/efi/0/Config/DmiSystemProduct" "iMac11,3"
VBoxManage setextradata "getmac-osx-mojave" "VBoxInternal/Devices/efi/0/Config/DmiSystemVersion" "1.0"
VBoxManage setextradata "getmac-osx-mojave" "VBoxInternal/Devices/efi/0/Config/DmiBoardProduct" "Iloveapple"
VBoxManage setextradata "getmac-osx-mojave" "VBoxInternal/Devices/smc/0/Config/DeviceKey" "ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc"
VBoxManage setextradata "getmac-osx-mojave" "VBoxInternal/Devices/smc/0/Config/GetKeyFromRealSMC" 1
VBoxManage modifyvm "getmac-osx-mojave" --cpu-profile "Intel Xeon X5482 3.20GHz"
```


Get version info:
```bash
sw_vers
system_profiler SPSoftwareDataType
```
