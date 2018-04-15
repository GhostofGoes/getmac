
# 0.2.0 (TBD)
## Added


## Changed
* CLI will output a blank string if it failed, instead of "None"
* CLI will always exit with a 0
* Added an argumnent for debugging: `--debug`
* Removed `-d` option from `--no-network-requests`

## Dev


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
