
## Setup
1. Install Android Studio
1. Install a emulator using Android SDK manager
1. Add 3 paths to the PATH environment variable: https://medium.com/@vsburnett/how-to-set-up-an-android-emulator-in-windows-10-e0a3284b5f94
    ```
    C:\Users\<user>\AppData\Local\Android\Sdk\platform-tools
    C:\Users\<user>\AppData\Local\Android\Sdk\emulator
    C:\Users\<user>\AppData\Local\Android\Sdk\tools\bin
    ```

## Resources
- https://developer.android.com/studio/run/emulator-commandline
- https://developer.android.com/studio/run/managing-avds
- https://developer.android.com/studio/command-line/adb


## Running Emulator
Create a AVD via Android Studio user interface under Tools -> AVD Manager. Then click the green play button next to the device to start.

Alternate method via CLI:
```powershell
emulator -list-avds
emulator -avd Nexus_4_API_23 -netdelay none -netspeed full
```

### Connect to the emulated device
```powershell
adb devices
adb shell
```


how do we add wifi?
"When using an AVD with API level 25 or higher, the emulator provides a simulated Wi-Fi access point ("AndroidWifi"), and Android automatically connects to it."
https://developer.android.com/studio/run/emulator.html#wifi


## Identifying Android in Python

```python
is_android = hasattr(sys, 'getandroidapilevel')
is_android = 'ANDROID_STORAGE' in environ

# Maybe? https://github.com/damonkohler/sl4a
is_android = 'AP_HANDSHAKE' in environ or "AP_HOST" in environ
```

## Scratchpad

Apparently some interfaces are limited on API 28

```bash
generic_x86_arm:/ $ cat /sys/class/net/wlan0/address
cat: /sys/class/net/wlan0/address: Permission denied

generic_x86_arm:/ $ ip link show wlan0
request send failed: Permission denied
1|generic_x86_arm:/ $ ip link show radio0
request send failed: Permission denied
1|generic_x86_arm:/ $ ip link show radio0@if10
request send failed: Permission denied

generic_x86_arm:/ $ ip route list 0/0
generic_x86_arm:/ $

generic_x86_arm:/ $ route -n
/system/bin/sh: route: not found
127|generic_x86_arm:/ $ route
/system/bin/sh: route: not found
127|generic_x86_arm:/ $

generic_x86_arm:/ $ arp
/system/bin/sh: arp: not found
127|generic_x86_arm:/ $ arp -a
/system/bin/sh: arp: not found


```