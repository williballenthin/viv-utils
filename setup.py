#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

import setuptools

requirements = [
    "funcy==1.18",
    "pefile>=2023.2.7",
    "vivisect==1.1.0",
    "intervaltree==3.1.0",
    "typing_extensions==4.5.0",
]

setuptools.setup(
    name="viv_utils",
    version="0.7.8",
    description="Utilities for binary analysis using vivisect.",
    long_description="Utilities for binary analysis using vivisect.",
    author="Willi Ballenthin",
    author_email="william.ballenthin@mandiant.com",
    url="https://github.com/williballenthin/viv-utils",
    packages=setuptools.find_packages(),
    package_dir={"viv_utils": "viv_utils"},
    package_data={"viv_utils": ["data/*.py"]},
    entry_points={
        "console_scripts": [
            "trace_function_emulation=viv_utils.scripts.trace_function_emulation:main",
            "get_function_args=viv_utils.scripts.get_function_args:main",
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        "flirt": [
            "python-flirt==0.8.6",
        ],
        "dev": [
            "pytest==7.2.1",
            "pytest-sugar==0.9.6",
            "pytest-instafail==0.4.2",
            "pycodestyle==2.10.0",
            "black==22.12.0",
            "isort==5.11.5",  # last version supporting Python 3.7
            "mypy==1.0.1",
            "types-setuptools==67.4.0.3",
        ],
    },
    zip_safe=False,
    keywords="viv_utils",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
    ],
)
