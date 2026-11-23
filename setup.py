from setuptools import setup, find_packages

setup(
    name="linux-vuln-scanner",
    version="1.0.0",
    author="Security Engineering Team",
    description="Linux Vulnerability Scanner and Security Assessment Report Generator",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "vulnscan": ["../data/*.json"],
    },
    entry_points={
        "console_scripts": [
            "vulnscan = vulnscan.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
)
