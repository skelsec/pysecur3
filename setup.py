from setuptools import setup, find_packages

setup(
	name='pySecur',
	version='0.1',
	packages=find_packages(exclude=['tests*','examples*']),
	license='None',
	description='BiSecur library for Python',
	install_requires=['enum34'],
	url='https://github.com/skelsec/pySecur',
	author='Tamas Jos',
	author_email='pysecur@skelsec.com'
)