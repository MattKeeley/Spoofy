from setuptools import setup

setup(
    name="Spoofy",
    version="1.1.0",
    packages=[ "modules" ],
    py_modules=["spoofy"],
    install_requires=[ "colorama", "dnspython>= 2.2.1", "tldextract", "pandas", "openpyxl", "requests" ],
    entry_points={ "console_scripts": [ "spoofy=spoofy:main" ] }
)

