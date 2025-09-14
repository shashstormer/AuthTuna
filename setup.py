from setuptools import setup, find_packages

with open("readme.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="authtuna",
    version="0.1.4",
    author="shashstormer",
    author_email="shashanka5398@gmail.com",
    description="A high-performance, framework-agnostic authorization and session management library for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shashstormer/authtuna",
    packages=find_packages(),
    package_data={
        'authtuna': ['templates/email/*.html', 'templates/pages/*.html'],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pydantic-settings>=2.0.0",
        "sqlalchemy>=2.0.0",
        "cryptography>=41.0.0",
        "pyotp>=2.8.0",
        "PyJWT>=2.8.0",
        "python-jose[cryptography]>=3.3.0",
        "aiosmtplib>=2.0.0",
        "dkimpy>=1.1.0",
        "slowapi>=0.1.0",
        "authlib>=1.0.0",
        "ua-parser>=0.10.0",
        "bcrypt>=4.0.0",
        "python-dotenv>=1.0.0",
        "qrcode>=7.4.2",
        "aiosqlite>=0.20.0",
        "fastapi>=0.100.0",
        "starlette>=0.27.0",
        "Jinja2>=3.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "httpx>=0.28.1"
        ],
    },
    include_package_data=True,
    zip_safe=False,
)