#!/usr/bin/env python3
"""
Agent Auth Protocol SDK for Python
"""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="trusted-agentic-commerce-protocol",
    version="0.3.0",
    author="Forter",
    author_email="support@forter.com",
    description="Python SDK implementing the Trusted Agentic Commerce Protocol for secure authentication and data encryption between AI agents, merchants and merchant vendors.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/forter/trusted-agentic-commerce-protocol",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "python-jose[cryptography]>=3.3.0",
        "aiohttp>=3.8.0",
    ],
    keywords=[
        "trusted-agentic-commerce",
        "tap-protocol",
        "agent",
        "authentication",
        "agentic-commerce",
        "jwt",
        "jwe",
        "jwks",
        "encryption",
    ],
    project_urls={
        "Bug Reports": "https://github.com/forter/trusted-agentic-commerce-protocol/issues",
        "Source": "https://github.com/forter/trusted-agentic-commerce-protocol",
    },
)
