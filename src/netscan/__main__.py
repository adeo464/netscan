"""Allow running netscan as a module: python -m netscan."""

from netscan.cli import app

if __name__ == "__main__":
    app()
