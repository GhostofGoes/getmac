Remove-Item .\getmac\ -ErrorAction SilentlyContinue -Recurse -Include *.pyc
Remove-Item .\getmac\ -ErrorAction SilentlyContinue -Recurse -Include *.pyo
Remove-Item .\getmac\ -ErrorAction SilentlyContinue -Recurse -Force -Include '__pycache__'

Remove-Item -ErrorAction SilentlyContinue -Force -Recurse .\build\
Remove-Item -ErrorAction SilentlyContinue -Force -Recurse .\dist\
Remove-Item -ErrorAction SilentlyContinue -Force -Recurse *.egg
Remove-Item -ErrorAction SilentlyContinue -Force -Recurse *.egg-info

Remove-Item -ErrorAction SilentlyContinue -Force -Recurse .\.tox\
Remove-Item -ErrorAction SilentlyContinue -Force -Recurse .\.pytest_cache\
Remove-Item -ErrorAction SilentlyContinue -Force -Recurse .\.mypy_cache\
Remove-Item -ErrorAction SilentlyContinue -Force -Recurse htmlcov
Remove-Item -ErrorAction SilentlyContinue -Force .coverage.coverage
