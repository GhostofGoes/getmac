# 0.2.4 (08/26/2018)
## Fixed
* Fixed identification of remote host on OSX
* Resolved hangs and noticable lag that occured when "network_request"
was True (the default)


# 0.2.3 (08/07/2018)
## Fixed
* Remote host for Python 3 on Windows


# 0.2.2 (08/02/2018)
## Added
* Attempt to use `psutil` (if available) to find interface MACs on all platforms
* Attempt to use `netifacts` (if available) to find interface MAC on Non-Windows platforms

## Changed
* Significantly improved the detection of the default interface

## Fixed
*

## Dev:
*

# 0.2.2
## Added
* Short versions of CLI arguments (e.g. "-i" for "--interface")

## Changed
* Improved usage of "ping" across platforms and IP versions
* Various minor tweaks for performance
* Improved Windows detection

## Fixed
* Use of ping command with hostname

## Dev:
* Improvements to internal code

# 0.2.1
Nothing changed. PyPI just won't let me push changes without a new version.


# 0.2.0 (04/15/2018)
## Added
* Checks for default interface on Linux systems
* New methods of hunting for addresses on Windows, Mac OS X, and Linux

## Changed
* CLI will output nothing if it failed, instead of "None"
* CLI will return with 1 on failure, 0 on success
* No CLI arguments now implies the default host network interface
* Added an argumnent for debugging: `--debug`
* Removed `-d` option from `--no-network-requests`

## Fixed
* Interfaces on Windows and Linux (including Bash for Windows)
* Many bugs

## Removed
* Support for Python 2.6 on the CLI

## Dev
* Overhaul of internals


# 0.1.0 (04/15/2018):
## Added
* Addition of a terminal command: `get-mac`
* Ability to run as a module from the command line: `python -m getmac`

## Changed
* `arp_request` argument was renamed to `network_request`
* Updated docstring
* Slight reduction in the size of getmac.py

## Dev
* Overhauled the README
* Moved tests into their own folder
* Added Python 3.7 to list of supported snakes


# 0.0.4 (11/12/2017):
* Python 2.6 compatibility


# 0.0.3 (11/11/2017):
* Fixed some addresses returning without colons
* Added more rigorous checks on addresses before returning them


# 0.0.2 (11/11/2017):
* Remove print statements and other debugging output


# 0.0.1 (10/23/2017):
* Initial pre-alpha
