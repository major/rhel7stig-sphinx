RHEL 7 STIG in Sphinx
=====================

This is an attempt to make the Red Hat Enterprise Linux 7 STIG a little easier
to work with by converting it into Sphinx documentation.

To build documentation:

.. code-block:: console

    $ pip install lxml jinja2 sphinx
    $ git clone https://github.com/major/rhel7stig-sphinx
    $ cd rhel7stig-sphinx
    $ stig/parser.py
    $ make -C doc html

