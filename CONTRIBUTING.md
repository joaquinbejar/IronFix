# Contributing to IronFix

We welcome contributions to IronFix! This document provides guidelines for contributing to the project and outlines the Git Flow methodology we expect our contributors to follow.

## Code of Conduct

By participating in this project, you are expected to uphold this code. Please report unacceptable behavior to [jb@taunais.com].

## How to Contribute

To contribute to IronFix, please follow these steps:

1. **Fork the repository**: Start by forking the IronFix repository to your GitHub account.

2. **Clone the repository**: After forking, clone the repository to your local machine to start making changes.

   ```bash
   git clone https://github.com/joaquinbejar/IronFix.git
   cd IronFix
   ```

3. **Adopt Git Flow**: We follow the Git Flow methodology for branch management. This involves maintaining two main branches with an infinite lifetime:
   - `main` for production releases, and
   - `develop` for integrating developed features.

4. **Branching**: Depending on what you are working on, you will either create:
   - A feature branch from develop named `feature/<your_feature_name>`.
   - A bugfix branch (if needed) also from develop named `bugfix/<your_bugfix_name>`.
   - Release branches (as needed) from develop to prepare for a new production release, named `release/<version>`.
   - Hotfix branches from main for quick fixes in production, named `hotfix/<version>`.

   Here’s how to start a new feature branch.

      ```bash
      git checkout -b feature/your_feature_name develop
      ```

5. **Make your changes**: Perform your changes in your feature branch.
6. **Commit your changes**: Write clear, concise commit messages that explain your modifications and their context.
7. **Push your changes**: Push your feature branch to your fork.

    ```bash
    git push origin feature/your_feature_name
    ```
8. **Create a Pull Request**: Go to the original IronFix repository you forked from. You should see a prompt to create a pull request from your newly pushed branch. Make sure your pull request targets the develop branch of the IronFix repository.

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a build.
2. Update the README.md with details of changes to the interface, this includes new environment variables, exposed ports, useful file locations, and container parameters.
3. Increase the version numbers in any examples files and the README.md to the new version that this Pull Request would represent. The versioning scheme we use is [SemVer](http://semver.org/) .
4. The pull request will be merged once you have the sign-off of two other developers, or if you do not have permission to do that, you may request the second reviewer to merge it for you.


**Thank you for contributing to IronFix!** We appreciate your efforts to improve financial messaging technology.
