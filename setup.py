#!/usr/bin/env python
# coding: utf-8


from setuptools import setup, find_packages


exec(open('micropayment_core/version.py').read())  # load __version__


setup(
    name='micropayment-core',
    scripts=[],
    description="Micropayment core utils for counterparty assets.",
    long_description=open("README.rst").read(),
    keywords="counterparty, micropayment, core",
    url='http://counterparty.io',
    author='Counterparty Developers',
    author_email='dev@counterparty.io',
    maintainer='Counterparty Developers',
    maintainer_email='dev@counterparty.io',
    license="MIT",
    version=__version__,  # NOQA
    test_suite="tests",
    dependency_links=[],
    package_data={'micropayment_core': []},
    include_package_data=True,
    install_requires=open("requirements.txt").readlines(),
    tests_require=open("requirements_tests.txt").readlines(),
    packages=find_packages(),
    classifiers=[
        # "Development Status :: 1 - Planning",
        # "Development Status :: 2 - Pre-Alpha",
        # "Development Status :: 3 - Alpha",
        "Development Status :: 4 - Beta",
        # "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
