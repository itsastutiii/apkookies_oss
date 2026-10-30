"""Test-wide settings: keep the pipeline's verdict store in memory so tests never
write a database into the working tree, and never pick up a real analyst token."""
import os

os.environ.setdefault("VERDICT_DB_PATH", ":memory:")
os.environ["ANALYST_TOKEN"] = ""
