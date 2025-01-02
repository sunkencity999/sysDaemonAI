from setuptools import setup, find_packages

setup(
    name="sysdaemonai",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "PyQt6",
        "psutil",
        "prometheus_client",
        "pytest",
        "pytest-asyncio",
        "pytest-qt",
        "pytest-cov",
        "pytest-timeout",
        "crewai"
    ],
)
