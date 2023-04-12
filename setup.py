from setuptools import setup, find_packages

setup(
    name="LocalResolver",
    version="1.0.1",
    py_modules=["LocalResolver"],
    install_requires=["scapy", "PythonToolsKit"],
    author="Maurice Lambert",
    author_email="mauricelambert434@gmail.com",
    maintainer="Maurice Lambert",
    maintainer_email="mauricelambert434@gmail.com",
    description="This package implements local hostname resolver tool with scapy.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/mauricelambert/LocalResolver",
    project_urls={
        "Executable": "https://mauricelambert.github.io/info/python/code/LocalResolver.pyz",
        "Documentation": "https://mauricelambert.github.io/info/python/code/LocalResolver.html",
    },
    classifiers=[
        "Environment :: Console",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
    entry_points={
        "console_scripts": ["LocalResolver = LocalResolver:main"],
    },
    python_requires=">=3.8",
    keywords=[
        "Resolve",
        "Hostname",
        "LLMNR",
        "Netbios",
    ],
    platforms=["Windows", "Linux", "MacOS"],
    license="GPL-3.0 License",
)
