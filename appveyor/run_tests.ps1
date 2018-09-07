Set-ExecutionPolicy Unrestricted
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -force
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -force
Get-ExecutionPolicy -List
echo $env:Path
echo "PYTHONPATH: $env:PYTHONPATH"
python --version
python -c "import platform; print(platform.architecture())"

echo "*** Beginning tests ***"

echo "get-mac --help"
get-mac --help

echo "get-mac --version"
get-mac --version

echo "python -m getmac --help"
python -m getmac --help

echo "python -m getmac --version"
python -m getmac --version

echo "get-mac"
get-mac

echo "python -m getmac"
python -m getmac

echo "get-mac --debug"
get-mac --debug

echo "python -m getmac --debug"
python -m getmac --debug

echo "get-mac --debug -i 'Ethernet'"
get-mac --debug -i 'Ethernet'

echo "get-mac --debug -4 127.0.0.1"
get-mac --debug -4 127.0.0.1

echo "get-mac --debug --no-network-requests -4 127.0.0.1"
get-mac --debug --no-network-requests -4 127.0.0.1

echo "get-mac --debug -n localhost"
get-mac --debug -n localhost

echo "*** Tests completed ***"
