# Contributing

Contributions are welcome when they preserve the project's defensive, authorization-first scope.

## Development setup

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python main.py
```

## Pull requests

1. Create a focused branch and keep changes small.
2. Add or update tests for behavior changes.
3. Run compilation and tests before submitting.
4. Update the README when commands, UI or data handling change.
5. Never commit credentials, wordlists, packet captures or real audit output.

Features that extract credentials, bypass access controls, evade security software, perform destructive actions or expand scanning beyond an explicitly authorized private scope will not be accepted.
