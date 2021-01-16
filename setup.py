from setuptools import setup, find_packages

setup(
    name = 'NetbiosSpoof',
 
    version = "0.0.3",
    packages = find_packages(include=["NetbiosSpoof"]),
    install_requires = ['scapy'],

    author = "Maurice Lambert", 
    author_email = "mauricelambert434@gmail.com",
 
    description = "This package implement a Hostname Spoofer (Netbios, LLMNR, DNS Local).",
    long_description = open('README.md').read(),
    long_description_content_type="text/markdown",
 
    include_package_data = True,

    url = 'https://github.com/mauricelambert/NetbiosSpoof',
 
    classifiers = [
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8"
    ],
 
    entry_points = {
        'console_scripts': [
            'NetbiosSpoof = NetbiosSpoof:netbiosspoofer'
        ],
    },
    python_requires='>=3.6',
)