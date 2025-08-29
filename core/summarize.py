"""Summarization constrained strictly to provided evidence snippets (citations-only policy).

Build final text using only snippets returned from retrieve().

No uncited claims. Include (doc/page/bbox) in footnotes or inline.

Keep an approval step before writing artifacts.
"""
