from setuptools import setup

# TODO move remaining things
setup(
    install_requires=[
        # TODO enable one authlib is released
        # "Authlib >= ?",
        # TODO remove once authlib released
        "cryptography",
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
            "pytest-mock==3.6.1",  # python 3.6+
            "mock==4.0.3",  # python 3.6+
        ]
    },
)
