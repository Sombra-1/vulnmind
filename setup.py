"""
setup.py — Package definition for VulnMind.

This file tells pip:
  - What the package is called
  - What Python version is required
  - What external libraries to install
  - What CLI command to create (the entry_points section)

After running `pip install -e .` in this directory, the `vulnmind` command
becomes available system-wide (or in the virtualenv).

The -e flag means "editable" install: changes to the source files take effect
immediately without reinstalling. Essential during development.
"""

from setuptools import setup, find_packages

setup(
    name="vulnmind",
    version="0.4.0",
    description="Security scan analyzer for pentesters",
    long_description=(open("README.md").read() if __import__("os").path.exists("README.md") else ""),
    long_description_content_type="text/markdown",
    author="sombra-1",
    python_requires=">=3.10",

    # find_packages() auto-discovers all directories with __init__.py
    # This finds: vulnmind/, vulnmind/parsers/
    packages=find_packages(),

    install_requires=[
        "click>=8.0",        # CLI framework (better than argparse)
        "rich>=13.0",        # Beautiful terminal output
        "requests>=2.28",    # HTTP client for Groq API calls
        "reportlab>=4.0",    # PDF generation
    ],

    # This is the magic: creates the `vulnmind` shell command.
    # Format: "command-name = package.module:function"
    # When the user types `vulnmind`, Python calls vulnmind.cli.cli()
    entry_points={
        "console_scripts": [
            "vulnmind=vulnmind.cli:cli",
        ],
    },

    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
