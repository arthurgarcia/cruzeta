CruZeta Core integration/staging tree
=====================================

https://cruzeta.org

What is CruZeta?
----------------

CruZeta is an experimental digital currency that enables instant payments to
anyone, anywhere in the world. CruZeta uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network. CruZeta Core is the name of open source
software which enables the use of this currency.

[CruZeta](https://cruzeta.org/) is an implementation of the "[Zerocash](https://github.com/zcash/zips/raw/master/protocol/protocol.pdf)" protocol forked from [ZCash](https://z.cash/).
Based on Bitcoin's code, it intends to offer a far higher standard of privacy
through a sophisticated zero-knowledge proving scheme that preserves
confidentiality of transaction metadata. 

For more information, as well as an immediately useable, binary version of
the CruZeta Core software, see [https://cruzeta.org](https://cruzeta.org).

License
-------

CruZeta Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/cruzeta-project/cruzeta/tags) are created
regularly to indicate new official, stable release versions of CruZeta Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

The Travis CI system makes sure that every pull request is built for Windows, Linux, and macOS, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

We only accept translation fixes that are submitted through [Bitcoin Core's Transifex page](https://www.transifex.com/projects/p/bitcoin/).
Translations are converted to CruZeta periodically.

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.

### Building

Build Zcash along with most dependencies from source by running:

```
./zcutil/build.sh -j$(nproc)
```

