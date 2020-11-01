"""The halogen python package."""
# coding=utf-8
import os
from setuptools import setup, find_packages
from halogen import __version__

setup(
    name="halogen",
    version=__version__,
    packages=find_packages(exclude=['docs', 'tests', 'tools', 'utils']),
    url="https://github.com/target/halogen/",
    license='Apache 2.0',
    author="Wyatt Roersma, Kyle Eaton",
    author_email="wyattroersma@gmail.com",
    description="This is the Python halogen library.",
    include_package_data=True,
    zip_safe=False,
    classifiers=['Development Status :: 4 - Beta',
                 'Intended Audience :: Developers',
                 'License :: OSI Approved :: Apache 2.0',
                 'Programming Language :: Python :: 3.7'],
    package_data={
        'halogen': ['*.txt'], 'halogen:data': ['*.txt', '*.yml', '*.json']
    },
    scripts=['halogen/halogencli.py'],
)
