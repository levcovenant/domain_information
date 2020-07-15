from setuptools import setup

setup(
    name='domaininfo',
    version='1.0',
    py_modules=['domain_info'],
    install_requires=[
        'Click',
        'pythonwhois',
        'dnspython',
    ],
    dependency_links=['https://github.com/levcovenant/python-whois/tarball/master'],
    entry_points="""
    [console_scripts]
    domain_info=dominfo:domain_info
    """,
)
