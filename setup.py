import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mitreattack_python",
    version="1.0.0",
    author="The MITRE Corporation",
    author_email="attack@mitre.org",
    description="MITRE ATT&CK python library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache 2.0",
    url="https://github.com/mitreattack-python/",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Development Statu || 4 - Beta",
        "License :: OSI Approved :: APACHE License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)

