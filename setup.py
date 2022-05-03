import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mitreattack-python",
    version="1.5.7",
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
            'attackToExcel_cli=mitreattack.attackToExcel.attackToExcel:main',
            'layerExporter_cli=mitreattack.navlayers.layerExporter_cli:main',
            'layerGenerator_cli=mitreattack.navlayers.layerGenerator_cli:main',
            'indexToMarkdown_cli=mitreattack.collections.index_to_markdown:main',
            'collectionToIndex_cli=mitreattack.collections.collection_to_index:main',
            'stixToCollection_cli=mitreattack.collections.stix_to_collection:main',
            'diff_stix=mitreattack.diffStix.changelog_helper:main'
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
        'colour',
        'drawSvg',
        'loguru',
        'Markdown',
        'numpy',
        'openpyxl',
        'pandas',
        'Pillow',
        'requests',
        'stix2',
        'stix2-elevator',
        'tabulate',
        'taxii2-client',
        'tqdm',
        'xlsxwriter',
    ]
)
