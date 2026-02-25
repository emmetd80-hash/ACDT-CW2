"""
ALC Breach Screener package entrypoint.

Allows running the application via:

    python -m alc_breach_screener

This delegates to `alc_breach_screener.screener.main()`.
"""

from .screener import main

if __name__ == "__main__":
    raise SystemExit(main())
