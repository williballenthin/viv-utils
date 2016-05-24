#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


requirements = [
    "funcy",
    "argparse",
    "pefile",
    "ipython",
    "vivisect",
    "intervaltree",
]

setup(
    name='viv_utils',
    version='0.3.5',
    description="Utilities for binary analysis using vivisect.",
    long_description="Utilities for binary analysis using vivisect.",
    author="Willi Ballenthin",
    author_email='william.ballenthin@mandiant.com',
    url='https://github.mandiant.com/wballenthin/viv-utils',
    packages=[
        'viv_utils',
    ],
    package_dir={'viv_utils':'viv_utils'},
    package_data={'viv_utils': ['data/*.py']},
    entry_points={
        "console_scripts": [
            "trace_function_emulation=viv_utils.scripts.trace_function_emulation:main",
            "get_function_args=viv_utils.scripts.get_function_args:main"
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    zip_safe=False,
    keywords='viv_utils',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
)

