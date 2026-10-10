"""Legitimate content must pass with minimal disruption."""
import pytest

from firewall import Verdict

BENIGN = [
    ("Can you summarize this article about renewable energy?", "user"),
    ("Please ignore the typo in my last message.", "user"),
    ("Explain prompt injection attacks such as 'ignore previous instructions' for my class.", "user"),
    ("Act as a travel guide and suggest a 3-day itinerary for Jaipur.", "user"),
    ("From now on, please answer in bullet points.", "user"),
    ("What does rm -rf do and why is it dangerous?", "user"),
    ("To keep your account secure, never share your password with anyone.", "text"),
    ("The system administrator will patch the servers on Saturday.", "text"),
    ("Step 1: unplug the router. Step 2: wait 30 seconds. Step 3: plug it back in.", "text"),
    ("Thumbnail: iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==", "text"),
    ("Commit 3f9a2c1d8e7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f fixes the login bug.", "text"),
    ("I love this! \U0001F468‍\U0001F469‍\U0001F467 Family trip was great.", "text"),
    ('{"id": 7, "name": "Teapot", "description": "Ceramic, 1 litre"}', "api_json"),
    ("# Install\nRun `pip install -r requirements.txt`.\n<!-- TODO: add docker -->", "markdown"),
    ("import shutil\n# Remove all cached files before rebuilding\nshutil.rmtree('build/cache')\n", "code"),
]


@pytest.mark.parametrize("text,source", BENIGN)
def test_benign_allowed(fw, text, source):
    r = fw.scan(text, source=source)
    assert r.verdict is Verdict.ALLOW, (r.summary(), [(f.rule_id, f.weighted_score) for f in r.findings])


def test_allowed_content_is_unchanged(fw):
    text = "The quarterly meeting moved to Thursday at 10am in room 4B."
    r = fw.scan(text, source="user")
    assert r.safe_text == text
