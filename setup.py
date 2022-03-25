import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mitreattack-python",
    version="1.4.6",
    author="MITRE ATT&CK, MITRE Corporation",
    author_email="attack@mitre.org",
    description="MITRE ATT&CK python library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    maintainer="Caleb Little",
    maintainer_email="clittle@mitre.org",
    license="Apache 2.0",
    url="https://github.com/mitre-attack/mitreattack-python/",
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'layerExporter_cli=mitreattack.navlayers.layerExporter_cli:main',
            'attackToExcel_cli=mitreattack.attackToExcel.attackToExcel:main',
            'layerGenerator_cli=mitreattack.navlayers.layerGenerator_cli:main',
            'indexToMarkdown_cli=mitreattack.collections.index_to_markdown:main',
            'collectionToIndex_cli=mitreattack.collections.collection_to_index:main',
            'stixToCollection_cli=mitreattack.collections.stix_to_collection:main'
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
        'stix2>=3.0.1',
        'taxii2-client>=2.3.0',
        'numpy>=1.16.0',
        'drawSvg>=1.6.0',
        'Pillow>=7.1.2',
        'pandas>=1.1.5',
        'tqdm>=4.31.1',
        'requests>=2.21.0',
        'xlsxwriter>=1.3.7',
        'tabulate>=0.8.9',
        'stix2-elevator>=4.0.1',
    ]
)
