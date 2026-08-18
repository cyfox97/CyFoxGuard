"""
core/auth_gate.py
Requirement 6: mandatory authorization gate before any scan runs. Interactive
"yes" confirmation in normal mode, or an environment variable in --ci mode.
Not skippable via any CLI flag — there is deliberately no --yes / --force
argument anywhere in the argument parser, and this function is the only
entry point that lets execution proceed past it.
"""
import os
import sys

CI_ENV_VAR = "CYFOXGUARD_AUTHORIZED"
CI_ENV_EXPECTED = "I_HAVE_AUTHORIZATION"

EXIT_UNAUTHORIZED = 2


def require_authorization(ci_mode: bool, target: str) -> None:
    """
    Blocks until authorization is affirmatively granted. Exits the process
    with code 2 if it is refused or, in --ci mode, not present. This is
    called unconditionally from cyfoxguard.py before any network module is
    imported/executed and cannot be bypassed by any flag combination.
    """
    print(
        "\nAUTHORIZATION REQUIRED\n"
        "You must have explicit, documented permission from the owner of the\n"
        f"target ({target}) to run security testing against it. Unauthorized\n"
        "scanning of systems you do not own or have written permission to test\n"
        "is illegal in most jurisdictions.\n"
    )

    if ci_mode:
        val = os.environ.get(CI_ENV_VAR, "")
        if val != CI_ENV_EXPECTED:
            print(
                f"[--ci mode] Environment variable {CI_ENV_VAR} is not set to "
                f"'{CI_ENV_EXPECTED}'. Refusing to scan. Set this variable in your\n"
                "pipeline configuration only after confirming authorization out of band.",
                file=sys.stderr,
            )
            sys.exit(EXIT_UNAUTHORIZED)
        print(f"[--ci mode] Authorization confirmed via {CI_ENV_VAR}.\n")
        return

    if not sys.stdin.isatty():
        print(
            "Not running in --ci mode and no interactive terminal is attached, "
            "so the authorization prompt cannot be answered safely. Refusing to scan.",
            file=sys.stderr,
        )
        sys.exit(EXIT_UNAUTHORIZED)

    try:
        answer = input(f'Type "yes" to confirm you are authorized to test {target}: ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""

    if answer != "yes":
        print("Authorization not confirmed. Exiting without sending any requests.", file=sys.stderr)
        sys.exit(EXIT_UNAUTHORIZED)

    print("Authorization confirmed.\n")
