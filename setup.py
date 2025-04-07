from setuptools import setup, find_packages

setup(
    name="netsecmonitor",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.4.5",
        "matplotlib>=3.5.0",
        "pandas>=1.3.5",
        "colorama>=0.4.4",
        "argparse>=1.4.0",
        "tqdm>=4.62.3",
        "netifaces>=0.11.0",
        "tabulate>=0.8.9",
        "python-whois>=0.7.3",
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="A Network Security Monitoring Tool",
    keywords="network, security, monitoring, intrusion-detection",
    url="https://github.com/yourusername/network-security-monitor",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Network Monitoring",
    ],
    python_requires=">=3.6",
)
