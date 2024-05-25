from setuptools import setup, find_packages

setup(
    name="bipsea",
    version="1.0",
    packages=find_packages(),
    description="Python implementation of BIP 85 (and BIP 32)",
    author="Aneesh Karve",
    author_email="bonded_metals_0u@icloud.com",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    keywords="Bitcoin BIP85  BIP32 cryptography",
    install_requires=[
        "click",
        "base58",
        "ecdsa",
        "pytest",
    ],
    tests_require=[
        "yamllint>=1.35.1",
    ],
    project_urls={
        "Source": "https://github.com/akarve/bipsea",
    },
)
