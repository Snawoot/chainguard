from os import path

from setuptools import setup

this_directory = path.abspath(path.dirname(__file__))  # pylint: disable=invalid-name
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()  # pylint: disable=invalid-name

setup(name='chainguard',
      version='0.0.1',
      description='TLS certificate chain watchdog which monitors hosts '
      'for malicious certificates issued by rogue CA',
      url='https://github.com/Snawoot/chainguard',
      author='Vladislav Yarmak',
      author_email='vladislav-ex-src@vm-0.com',
      license='MIT',
      packages=['chainguard'],
      python_requires='>=3.5',
      setup_requires=[
          'wheel',
      ],
      install_requires=[
          'cryptography>=1.6',
          'pyOpenSSL>=17.1.0',
      ],
      entry_points={
          'console_scripts': [
              'chainguard=chainguard.__main__:main',
          ],
      },
      classifiers=[
          "Programming Language :: Python :: 3.4",
          "License :: OSI Approved :: MIT License",
          "Operating System :: OS Independent",
          "Development Status :: 3 - Alpha",
          "Environment :: Console",
          "Intended Audience :: Telecommunications Industry",
          "Intended Audience :: System Administrators",
          "Intended Audience :: Other Audience",
          "Natural Language :: English",
          "Topic :: Internet",
          "Topic :: Security",
          "Topic :: Security :: Cryptography",
          "Topic :: Utilities",
      ],
      long_description=long_description,
      long_description_content_type='text/markdown',
      zip_safe=True)
