#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

import setuptools

requirements = [
    "funcy==1.17",
    "pefile==2022.5.30",
    "vivisect==1.0.8",
    "intervaltree==3.1.0",
    "typing_extensions==4.2.0",
]

setuptools.setup(
    name="viv_utils",
    version="0.7.6",
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
            "python-flirt==0.8.4",
        ],
        "dev": [
            "pytest==7.2.0",
            "pytest-sugar==0.9.4",
            "pytest-instafail==0.4.2",
            "pycodestyle==2.10.0",
            "black==22.12.0",
            "isort==5.10.1",
            "mypy==0.991",
            "types-setuptools==65.6.0.2",
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
