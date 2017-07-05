#!/usr/bin/env python3

from setuptools import setup

setup(name='b2stream',
      version='0.1',
      description='Store streaming encrypted data on B2',
      url='http://github.com/eminescu/b2stream',
      author='eminescu',
      author_email='eminescu@libero.it',
      license='MIT',
      packages=['b2stream'],
      scripts=['b2receive', 'b2send'],
      install_requires=[ 'b2', 'progress', 'cryptography' ],
      zip_safe=False)

