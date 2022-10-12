# Configuration file for the Sphinx documentation builder.
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
project = 'mitreattack-python'
copyright = '2022, The MITRE Corporation'
version = '2.0.0'
release = '2.0.0'

# -- General configuration ---------------------------------------------------
extensions = []
add_module_names = True
show_authors = True
templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

