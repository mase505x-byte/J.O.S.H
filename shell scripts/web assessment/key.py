"""Server-side helpers for accessing the Anthropic API key.

Keys may come from the server environment or be held in memory for the current
server session. Never put them in source control or return them to a client.
"""

import os
import threading

_lock = threading.Lock()
_session_key = None
_session_key_cleared = False


def set_session_api_key(api_key: str) -> None:
	"""Keep a key in memory for this server process only."""
	global _session_key, _session_key_cleared
	with _lock:
		_session_key = api_key
		_session_key_cleared = False


def clear_session_api_key() -> None:
	"""Forget any session key and suppress the environment fallback."""
	global _session_key, _session_key_cleared
	with _lock:
		_session_key = None
		_session_key_cleared = True


def get_api_key() -> str:
	"""Return the configured API key or fail with a safe error message."""
	with _lock:
		if _session_key:
			return _session_key
		if _session_key_cleared:
			raise RuntimeError("ANTHROPIC_API_KEY is not configured")
	api_key = os.getenv("ANTHROPIC_API_KEY")
	if not api_key:
		raise RuntimeError("ANTHROPIC_API_KEY is not configured")
	return api_key


def get_api_headers() -> dict[str, str]:
	"""Build headers for server-side Anthropic API requests."""
	return {
		"x-api-key": get_api_key(),
		"anthropic-version": "2023-06-01",
		"content-type": "application/json",
	}
