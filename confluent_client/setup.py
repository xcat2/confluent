from setuptools import setup

setup(
    name='confluent_client',
    version='0.1.1',
    author='Jarrod Johnson',
    author_email='jbjohnso@us.ibm.com',
    url='http://xcat.sf.net/',
    packages=['confluent'],
    install_requires=['confluent_common>=0.1.1'],
    scripts=['bin/confetty'],
)
