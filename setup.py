from setuptools import setup

setup(
    name="Spoofy",
    version="1.0.2",
    packages=[ "modules", "files" ],
    py_modules=["spoofy"],
    install_requires=[ "colorama", "dnspython>= 2.2.1", "tldextract", "pandas", "openpyxl" ],
    entry_points={ "console_scripts": [ "spoofy=spoofy:main" ] }
)

