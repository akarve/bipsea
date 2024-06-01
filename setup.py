from setuptools import find_packages, setup

from src.bipsea.util import __app_name__, __version__

setup(
    name=__app_name__,
    version=__version__,
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    package_data={
        __app_name__: ["english.txt"],
    },
    description="Python implementation of BIP 85 (and BIP 32)",
    author="Aneesh Karve",
    author_email="bonded_metals_0u@icloud.com",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="Bitcoin BIP85 BIP32 cryptography",
    install_requires=[
        "click",
        "base58",
        "ecdsa",
        "pytest",
    ],
    tests_require=[
        "black",
        "isort",
        "pytest",
        "requests",
    ],
    project_urls={
        "Source": "https://github.com/akarve/bipsea",
    },
    entry_points={
        "console_scripts": [
            "bipsea=bipsea.bipsea:cli",
        ],
    },
)
