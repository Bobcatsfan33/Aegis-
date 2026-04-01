"""
Shared pytest fixtures for the AegisAI test suite.
"""

import os
import sys

# Ensure the project root is on the path so modules can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
