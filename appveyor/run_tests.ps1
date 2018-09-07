Set-ExecutionPolicy Unrestricted
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -force
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -force
Get-ExecutionPolicy -List
echo $env:Path
echo "PYTHONPATH: $env:PYTHONPATH"
echo $env:ci_type
python --version
python -c "import platform; print(platform.architecture())"

get-mac --help
get-mac --version
python -m get-mac --help
python -m get-mac --version

get-mac
python -m get-mac
get-mac --debug
python -m get-mac --debug

get-mac --debug -i 'Ethernet'
get-mac --debug -4 127.0.0.1
get-mac --debug --no-network-requests -4 127.0.0.1
get-mac --debug -n localhost
