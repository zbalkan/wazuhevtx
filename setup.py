from setuptools import setup

setup(
    name='wazuhevtx',
    version='0.1.0',
    description='Dump a binary EVTX file into JSON with a standardized structure Wazuh agent uses',
    url='https://github.com/zbalkan/wazuh-evtx',
    author='Zafer Balkan',
    author_email='zafer@zaferbalkan.com',
    license='MIT',
    packages=['wazuhevtx'],
    install_requires=['pywin32==308',
                      'xmltodict==0.14.2',
                      ],

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.14',
    ],
)
