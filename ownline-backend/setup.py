from setuptools import setup

setup(
    name='ownline-backend',
    packages=['ownline_backend'],
    include_package_data=True,
    install_requires=[
        'flask',
    ],
)