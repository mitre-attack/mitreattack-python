import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mitreattack-python",
    version="1.2.0",
    author="MITRE ATT&CK, MITRE Corporation",
    author_email="attack@mitre.org",
    description="MITRE ATT&CK python library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    maintainer="Caleb Little",
    maintainer_email="clittle@mitre.org",
    license="Apache 2.0",
    url="https://github.com/mitreattack-python/",
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'layerExporter_cli=mitreattack.navlayers.layerExporter_cli:main',
            'attackToExcel_cli=mitreattack.attackToExcel.attackToExcel:main'
        ]
    },
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        'colour>=0.1.5',
        'openpyxl>=3.0.3',
        'stix2>=1.1.2',
        'taxii2-client>=2.2.1',
        'numpy>=1.16.0',
        'drawSvg>=1.6.0',
        'Pillow>=7.1.2',
        'pandas>=1.1.5',
        'tqdm>=4.31.1',
        'requests>=2.21.0',
        'xlsxwriter>=1.3.7',
    ]
)
