"""
setup.py
Packages ReconToReport so it can be installed and run as a standalone
command — `rtr` — from anywhere, instead of `python3 main.py` from inside
the project folder. Same pattern tools like Metasploit (`msfconsole`) or
AutoRecon (`autorecon`) use.

Install:
    pip3 install -e . --break-system-packages

Then run from anywhere:
    rtr --target 10.10.10.5
"""

from setuptools import setup, find_packages

setup(
    name="reconToReport",
    version="1.0.0",
    description="Automated Recon-to-Report Pentesting Pipeline",
    author="Ra_one",
    py_modules=["main"],
    packages=find_packages(include=["core", "core.*", "modules", "modules.*",
                                     "vuln", "vuln.*", "report", "report.*",
                                     "utils", "utils.*"]),
    install_requires=[
        "python-dotenv>=1.0,<2.0",
        "md2pdf>=1.0,<2.0",
        "argcomplete>=3.0,<4.0",
    ],
    entry_points={
        "console_scripts": [
            "rtr=main:main",
        ],
    },
    python_requires=">=3.10",
)