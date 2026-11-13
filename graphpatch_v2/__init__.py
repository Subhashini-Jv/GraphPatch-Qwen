"""GraphPatch v2: graph-verified multi-agent repair of Java vulnerabilities.

A patch counts as a fix only when the project builds, its tests show no new
failures, and the source-to-sink taint path found on the vulnerable code is gone.
"""

__version__ = "v3.5.1"
