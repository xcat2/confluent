from setuptools import setup

setup(
    name='confluent_server',
    version='0.1.10',
    author='Jarrod Johnson',
    author_email='jbjohnso@us.ibm.com',
    url='http://xcat.sf.net/',
    description='confluent systems management server',
    packages=['confluent', 'confluent/config', 'confluent/interface',
              'confluent/plugins/hardwaremanagement/',
              'confluent/plugins/configuration/'],
    install_requires=['pycrypto>=2.6', 'confluent_client>=0.1.0', 'eventlet',
                      'pyghmi>=0.6.5'],
    scripts=['bin/confluent'],
)
