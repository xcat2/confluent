from setuptools import setup

setup(
    name='confluent_server',
    version='0.1.0',
    author='Jarrod Johnson',
    author_email='jbjohnso@us.ibm.com',
    url='http://xcat.sf.net/',
    packages=['confluent', 'confluent/config', 'confluent/interface'],
    install_requires=['pycrypto>=2.6', 'confluent_client>=0.1.0'],
    scripts=['bin/confluent'],
)
