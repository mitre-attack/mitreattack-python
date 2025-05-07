import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mitreattack-python",
    version="4.0.2",
    author="MITRE ATT&CK, MITRE Corporation",
    author_email="attack@mitre.org",
    description="MITRE ATT&CK python library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    maintainer="Jared Ondricek",
    maintainer_email="jondricek@mitre.org",
    license="Apache 2.0",
    url="https://github.com/mitre-attack/mitreattack-python/",
    package_data={"mitreattack": ["navlayers/exporters/fonts/*.ttf"]},
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "attackToExcel_cli=mitreattack.attackToExcel.attackToExcel:main",
            "layerExporter_cli=mitreattack.navlayers.layerExporter_cli:main",
            "layerGenerator_cli=mitreattack.navlayers.layerGenerator_cli:main",
            "indexToMarkdown_cli=mitreattack.collections.index_to_markdown:main",
            "collectionToIndex_cli=mitreattack.collections.collection_to_index:main",
            "diff_stix=mitreattack.diffStix.changelog_helper:main",
            "download_attack_stix=mitreattack.download_stix:app",
        ]
    },
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=[
        "colour",
        "deepdiff",
        "drawsvg>=2.0.0",
        "loguru",
        "Markdown",
        "numpy",
        "openpyxl",
        "pandas",
        "pooch",
        "python-dateutil",
        "Pillow",
        "requests",
        "rich",
        "stix2",
        "tabulate",
        "tqdm",
        "typer",
        "xlsxwriter",
    ],
)
