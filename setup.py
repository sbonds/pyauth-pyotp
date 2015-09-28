#!/usr/bin/env python

import os, glob
from setuptools import setup, find_packages

install_requires = [line.rstrip() for line in open(os.path.join(os.path.dirname(__file__), "requirements.txt"))]

setup(
    name='pyotp',
    version='2.0.1',
    url='https://github.com/pyotp/pyotp',
    license='BSD License',
    author='PyOTP contributors',
    author_email='kislyuk@gmail.com',
    description='Python One Time Password Library',
    long_description=open('README.rst').read(),
    install_requires=install_requires,
    packages=['pyotp'],
    package_dir={'': 'src'},
    platforms=['MacOS X', 'Posix'],
    zip_safe=False,
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
