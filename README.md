# IronFix

IronFix is a robust and efficient Rust-based implementation of the Financial Information eXchange (FIX) protocol, designed for secure and high-performance financial messaging.

## Features

- **High Performance**: Engineered to handle high throughput and low latency for financial messaging.
- **Security**: Leverages Rust's memory safety features to reduce the risk of common bugs and vulnerabilities.
- **Easy Integration**: Designed to be easily integrated into existing financial systems.
- **Session Management**: Automatic management of session states and message sequencing.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

What things you need to install the software and how to install them:

```bash
# Example: Installation of Rust and Cargo (Rust's package manager)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Installing
A step-by-step series of examples that tell you how to get a development environment running:

```bash
# Clone the repository
git clone https://github.com/joaquinbejar/IronFix.git
# Go into the repository
cd IronFix
# Build the project
cargo build
```

### Running the tests

```bash
cargo test
```

### Deployment
Add additional notes about how to deploy this on a live system.

### Contributing
Please read CONTRIBUTING.md for details on our code of conduct, and the process for submitting pull requests to us.

### Versioning

We use [SemVer](http://semver.org/) for versioning. This approach allows us to maintain a clear, predictable system for version management. Under this scheme, version numbers are given in the format of `MAJOR.MINOR.PATCH`, where:

- `MAJOR` versions indicate incompatible API changes,
- `MINOR` versions add functionality in a backwards-compatible manner, and
- `PATCH` versions include backwards-compatible bug fixes.

This standard helps users and developers to understand the impact of new updates at a glance. For the versions available, see the [tags on this repository](https://github.com/joaquinbejar/IronFix/tags).


### Authors
Joaquín Béjar García - Initial work - [joaquinbejar](https://github.com/joaquinbejar)

See also the list of contributors who participated in this project.

### License
This project is licensed under the MIT License - see the LICENSE.md file for details.

### Acknowledgments
Will be added in the future.
```