"""Clean up old build artefacts."""
import shutil


def clean():
    # Remove all cached files before rebuilding
    shutil.rmtree('build/cache', ignore_errors=True)
