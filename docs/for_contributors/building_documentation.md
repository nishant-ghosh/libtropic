# Building the Documentation
Libtropic documentation is built using the following two frameworks, each generating a different part of the documentation:

1. [MkDocs](https://www.mkdocs.org/), used to generate the pages you are seeing now,
2. [Doxygen](https://www.doxygen.nl/), used to generate the API Reference from the Libtropic source code.

Normally, you do not need to build the documentation yourself; it is available on our [GitHub Pages](https://tropicsquare.github.io/libtropic/latest/), where versions for all [releases](https://github.com/tropicsquare/libtropic/releases) are automatically built and released by our GitHub Actions. However, when contributing to the documentation, it is useful to build it locally and preview changes. See the following sections for instructions.

## Install the Dependencies
!!! example "Installing dependencies"
    === ":fontawesome-brands-linux: Linux"
        First, install MkDocs dependencies:

        1. [Install Python](https://www.python.org/downloads/) (version 3.8 or later)
            - You can also use your distribution's package manager:
                - Fedora: `sudo dnf install python3`
                - Debian/Ubuntu: `sudo apt update && sudo apt install python3`
        2. We recommend creating a [Python virtual environment](https://docs.python.org/3/library/venv.html), for example named `.docs-venv`:
        ```bash { .copy }
        python3 -m venv .docs-venv
        source .docs-venv/bin/activate
        ```
        3. Update `pip` and install the required packages from `docs/requirements.txt`:
        ```bash { .copy }
        pip install --upgrade pip
        pip install -r docs/requirements.txt
        ```
        
        After that, install **Doxygen** and **Graphviz** (used for diagrams):
        
        - Fedora: `sudo dnf install doxygen graphviz`
        - Debian/Ubuntu: `sudo apt update && sudo apt install doxygen graphviz`

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

## Build Doxygen Documentation
First, build the API Reference using Doxygen:

!!! example "Building Doxygen Documentation"
    === ":fontawesome-brands-linux: Linux"
        1. Switch to `docs/doxygen/`:
        ```bash { .copy }
        cd docs/doxygen/
        ```
        2. Build:
        ```bash { .copy }
        doxygen Doxyfile.in
        ```

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

The API Reference should now be built in `docs/doxygen/build/html/`.

!!! warning
    These steps have to be done each time the contents of `docs/doxygen/` change and you want to preview the changes.

## Build MkDocs Documentation
MkDocs can run a built-in development server on localhost that serves the documentation. To run it, switch to the root Libtropic directory (where `mkdocs.yml` is located) and run:

!!! example "Building MkDocs Documentation"
    === ":fontawesome-brands-linux: Linux"
        ```bash { .copy }
        mkdocs serve --livereload
        ```
        In the terminal, you should see the address of the server. To open it in your browser, press <kbd>Ctrl</kbd> + <kbd>:material-mouse-left-click: Left Click</kbd> or copy the address manually.

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

!!! warning
    MkDocs does not rebuild the Doxygen documentation automatically; to rebuild it, repeat the steps from section [Build Doxygen Documentation](#build-doxygen-documentation).

!!! tip
    You do not need to stop and restart the server each time you edit files inside `docs/`; the server reloads content automatically on each save.

## Versioned Documentation
When you build the documentation locally using the steps in [Build MkDocs Documentation](#build-mkdocs-documentation), the version selector in the page header is not visible as it is on our [GitHub Pages](https://tropicsquare.github.io/libtropic/latest/). That's because we use the [mike](https://github.com/jimporter/mike) plugin for MkDocs for versioning. This plugin maintains the `gh-pages` branch, from which GitHub Pages are deployed.

### Preview the Versioned Documentation
The most common and safe use case is to locally preview the state of the documentation that is deployed to our [GitHub Pages](https://tropicsquare.github.io/libtropic/latest/):
!!! example "Previewing the Versioned Documentation"
    === ":fontawesome-brands-linux: Linux"
        1. Make sure you have the latest version of the `gh-pages` branch from `origin`:
        ```bash { .copy }
        git fetch origin gh-pages:gh-pages
        ```
        Do not `git checkout gh-pages`, because you will not be able to build the documentation there. Instead, `git checkout` `master`, `develop`, or any other branch based on one of these.
        2. Run a built-in development server with the contents of `gh-pages`:
        ```bash { .copy }
        mike serve
        ```
        
        In the terminal, you should see the address of the server. To open it in your browser, press <kbd>Ctrl</kbd> + <kbd>:material-mouse-left-click: Left Click</kbd> or just manually copy it.

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

### Edit the Versioned Documentation
!!! danger
    Some of the following commands change the state of the local `git` repository, specifically the `gh-pages` branch, and possibly the `origin` remote!

If you need to deploy a new version locally and preview it, you must modify the `gh-pages` branch:
!!! example "Locally Deploying a New Version"
    === ":fontawesome-brands-linux: Linux"
        ```bash { .copy }
        mike deploy <version_name>
        ```
        After running this, the `gh-pages` branch will be **created** (if it does not already exist) and the generated documentation will be **pushed** to it.
        !!! danger
            If you add the `--push` flag, the `gh-pages` branch will be pushed to `origin` — **we do not recommend doing that!** This applies to most `mike` commands.
    
    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

To see all existing versions, do:
!!! example "Seeing Existing Versions"
    === ":fontawesome-brands-linux: Linux"
        ```bash { .copy }
        mike list
        ```
        !!! info
            This command is safe — it does not change the `gh-pages` branch.

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

To remove a specific version, do:
!!! example "Deleting Existing Version"
    === ":fontawesome-brands-linux: Linux"
        ```bash { .copy }
        mike delete <version_name>
        ```

    === ":fontawesome-brands-apple: macOS"
        TBA

    === ":fontawesome-brands-windows: Windows"
        TBA

There are more commands available — refer to the [mike repository](https://github.com/jimporter/mike) for more information.