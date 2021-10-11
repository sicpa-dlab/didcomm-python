from setuptools import setup

# TODO move remaining things
setup(
    install_requires=[
        # TODO switch to authlib stable release version once it appears
        "Authlib>=1.0.0b1",
        "pycryptodomex~=3.10",
        "base58~=2.1",
        "varint~=1.0.2",
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
