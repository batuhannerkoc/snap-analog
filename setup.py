from setuptools import setup, find_packages

setup(
    name="snap-analog",
    version="2.0",
    author="Batuhan Erkoc",
    description="High-performance log analysis and visualization toolkit",
    packages=find_packages(where="src"),  # src altındaki tüm paketleri bul
    package_dir={"": "src"},               # src klasörü baz alınıyor
    entry_points={
        "console_scripts": [
            "snap-analog=cli:main",       # cli.py içindeki main fonksiyonunu çağırır
        ],
    },
    python_requires=">=3.8",
    install_requires=[
        "pandas>=1.5",
        "matplotlib>=3.6",
        "seaborn>=0.12",
        "ipaddress",
        "psutil",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)

