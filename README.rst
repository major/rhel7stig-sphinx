RHEL 7 STIG in Sphinx
=====================

This is an attempt to make the `Red Hat Enterprise Linux 7 Security Technical
Implementation Guide (STIG)`_ a little easier to work with by converting it into
Sphinx documentation.

.. _Red Hat Enterprise Linux 7 Security Technical Implementation Guide (STIG): http://iase.disa.mil/stigs/os/unix-linux/Pages/index.aspx

Pre-built documentation is available here:

* http://rhel7stig.rtfd.io/

To build documentation:

.. code-block:: console

    $ pip install -r requirements.txt
    $ git clone https://github.com/major/rhel7stig-sphinx
    $ cd rhel7stig-sphinx
    $ stig/parser.py
    $ make -C doc html

