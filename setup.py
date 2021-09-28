import pathlib

from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name="didcomm",
    version="0.1.0",
    description="DIDComm for Python",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/sicpa-dlab/didcomm-python",
    author="SICPA",
    author_email="DLCHOpenSourceContrib@sicpa.com",
    license="Apache-2.0",
    python_requires=">=3.7",
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    packages=find_packages(exclude=['tests', 'tests.*']),
    install_requires=[
        # TODO switch to pypi once necessary authlib version is released
        "Authlib@git+https://github.com/lepture/authlib.git@7bfd5590cc365803633c56e784b43494589abff2",
        "pycryptodomex~=3.10",
        "attrs~=21.2",  # TODO explore lowest acceptable version
        "packaging~=21.0",  # TODO explore lowest acceptable version
    ],
    extras_require={
        "tests": [
            "pytest==6.2.5",
            "pytest-asyncio==0.15.1",
            "pytest-xdist==2.3.0",
            "flake8==3.9.2",
            "black==21.9b0",
            "pytest-mock==3.6.1",  # NOTE python 3.6+
            "mock==4.0.3",  # NOTE python 3.6+
        ]
    },
)
