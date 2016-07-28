
High
====




RHEL-07-010010 - The file permissions, ownership, and group membership of system files and commands must match the vendor values.
---------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Discretionary access control is weakened if a user or group has access permissions to system files and directories greater than the default.

Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000278-GPOS-00108

Check
~~~~~

Verify the file permissions, ownership, and group membership of system files and commands match the vendor values.
Check the file permissions, ownership, and group membership of system files and commands with the following command:

# rpm -Va | grep '^.M'

If there is any output from the command, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-001494, CCI-001496


----




RHEL-07-010020 - The cryptographic hash of system files and commands must match vendor values.
----------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Without cryptographic integrity protections, system command and files can be altered by unauthorized users without detection.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

Check
~~~~~

Verify the cryptographic hash of system files and commands match the vendor values.

Check the cryptographic hash of system files and commands with the following command:

Note: System configuration files (indicated by a "c" in the second column) are expected to change over time. Unusual modifications should be investigated through the system audit log.

# rpm -Va | grep '^..5'

If there is any output from the command for system binaries, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000663


----




RHEL-07-010260 - The system must not have accounts configured with blank or null passwords.
-------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

Check
~~~~~

To verify that null passwords cannot be used, run the following command: 

# grep nullok /etc/pam.d/system-auth

If this produces any output, it may be possible to log on with accounts with empty passwords.

If null passwords can be used, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-010270 - The SSH daemon must not allow authentication using an empty password.
--------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.

Check
~~~~~

To determine how the SSH daemon's "PermitEmptyPasswords" option is set, run the following command:

# grep -i PermitEmptyPasswords /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "no" is returned, the required value is set.

If the required value is not set, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000766


----




RHEL-07-010430 - The operating system must not allow an unattended or automatic logon to the system via a graphical user interface.
-----------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Failure to restrict system access to authenticated users negatively impacts operating system security.

Check
~~~~~

Verify the operating system does not allow an unattended or automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check for the value of the “AutomaticLoginEnable” in “/etc/gdm/custom.conf” file with the following command:

# grep -i automaticloginenable /etc/gdm/custom.conf
AutomaticLoginEnable=false

If the value of “AutomaticLoginEnable” is not set to “false”, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-010431 - The operating system must not allow guest logon to the system.
-------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Failure to restrict system access to authenticated users negatively impacts operating system security.

Check
~~~~~

Verify the operating system does not allow guest logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check for the value of the “AutomaticLoginEnable” in “/etc/gdm/custom.conf” file with the following command:

# grep -i timedloginenable /etc/gdm/custom.conf
TimedLoginEnable=false

If the value of “TimedLoginEnable” is not set to “false”, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-010440 - The operating system must not allow empty passwords for SSH logon to the system.
-------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Failure to restrict system access to authenticated users negatively impacts operating system security.

Check
~~~~~

Verify the operating system does not allow empty passwords to be used for SSH logon to the system.

Check for the value of the PermitEmptyPasswords keyword with the following command:

# grep -i permitemptypassword /etc/ssh/sshd_config
PermitEmptyPasswords no

If the “PermitEmptyPasswords” keyword is not set to “no”, is missing, or is commented out, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-010460 - Systems with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes.
-------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

Check
~~~~~

Check to see if an encrypted root password is set. On systems that use a BIOS, use the following command:

# grep -i password /boot/grub2/grub.cfg
password_pbkdf2 superusers-account password-hash

If the root password entry does not begin with “password_pbkdf2”, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000213


----




RHEL-07-010470 - Systems using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes.
------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

Check
~~~~~

Check to see if an encrypted root password is set. On systems that use UEFI, use the following command:

# grep -i password /boot/efi/EFI/redhat/grub.cfg
password_pbkdf2 superusers-account password-hash

If the root password entry does not begin with “password_pbkdf2”, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000213


----




RHEL-07-020000 - The rsh-server package must not be installed.
--------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

The rsh-server service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session and has very weak authentication.

If a privileged user were to log on using this service, the privileged user password could be compromised.

Check
~~~~~

Check to see if the rsh-server package is installed with the following command:

# yum list installed | grep rsh-server

If the rsh-server package is installed, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000381


----




RHEL-07-020010 - The ypserv package must not be installed.
----------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.

Check
~~~~~

The NIS service provides an unencrypted authentication service that does not provide for the confidentiality and integrity of user passwords or the remote session.

Check to see if the “ypserve” package is installed with the following command:

# yum list installed | grep ypserv

If the “ypserv” package is installed, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000381


----




RHEL-07-020150 - The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.

Check
~~~~~

Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components from a repository without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.

Check that yum verifies the signature of packages from a repository prior to install with the following command:

# grep gpgcheck /etc/yum.conf
gpgcheck=1

If "gpgcheck" is not set to ”1”, or if options are missing or commented out, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-001749


----




RHEL-07-020151 - The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.

Check
~~~~~

Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.

Check that yum verifies the signature of local packages prior to install with the following command:

# grep localpkg_gpgcheck /etc/yum.conf
localpkg_gpgcheck=1

If "localpkg_gpgcheck" is not set to ”1”, or if options are missing or commented out, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-001749


----




RHEL-07-020152 - The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of packages without verification of the repository metadata.
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved Certificate Authority.

Check
~~~~~

Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification of the repository metadata.

Check that yum verifies the package metadata prior to install with the following command:

# grep repo_gpgcheck /etc/yum.conf
repo_gpgcheck=1

If "repo_gpgcheck" is not set to ”1”, or if options are missing or commented out, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-001749


----




RHEL-07-020170 - Operating systems handling data requiring data-at-rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Selection of a cryptographic mechanism is based on the need to protect the integrity and confidentiality of sensitive information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). This requirement is applicable if the organization determines that its sensitive information is to be protected at the storage device level.

Satisfies: SRG-OS-000405-GPOS-00184, SRG-OS-000185-GPOS-00079

Check
~~~~~

Verify the operating system, if handling data that requires protection to prevent the unauthorized discloser or modification of information at rest, is using disk encryption. 

Note: If the organization determines that no data resident on the system requires protection, or that sensitive data is being protected through an application encryption mechanism, this requirement is Not Applicable.

Check the system partitions to determine if they are all encrypted with the following command:

# blkid
/dev/sda1: UUID=" ab12c3de-4f56-789a-8f33-3850cc8ce3a2
" TYPE="crypto_LUKS"
/dev/sda2: UUID=" bc98d7ef-6g54-321h-1d24-9870de2ge1a2
" TYPE="crypto_LUKS"

Pseudo-file systems, such as /proc, /sys, and tmpfs, are not required to use disk encryption and are not a finding. 

If any other partitions do not have a type of “crypto_LUKS”, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: NEW

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-002476, CCI-001199


----




RHEL-07-020210 - The operating system must enable SELinux.
----------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

Check
~~~~~

Verify the operating system verifies correct operation of all security functions.

Check if SELinux is active and in enforcing mode with the following command:

# getenforce
Enforcing

If the “SELinux” mode is not set to “Enforcing”, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-002165, CCI-002696


----




RHEL-07-020211 - The operating system must enable the SELinux targeted policy.
------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

Check
~~~~~

Verify the operating system verifies correct operation of all security functions.

Check if SELinux is active and is enforcing the targeted policy with the following command:

# sestatus
SELinux status:                 enabled
SELinuxfs mount:                /selinux
Current mode:                   enforcing
Mode from config file:          enforcing
Policy version:                 24
Policy from config file:        targeted

If the “Policy from config file”  not set to “targeted”, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: NEW

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-002165, CCI-002696


----




RHEL-07-020220 - The x86 Ctrl-Alt-Delete key sequence must be disabled.
-----------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

Check
~~~~~

Verify the operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

Check that the ctrl-alt-del.service is not active with the following command:

# systemctl status ctrl-alt-del.service
reboot.target - Reboot
   Loaded: loaded (/usr/lib/systemd/system/reboot.target; disabled)
   Active: inactive (dead)
     Docs: man:systemd.special(7)

If the ctrl-alt-del.service is active , this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: NEW

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-020240 - The operating system must be a supported release.
------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

Check
~~~~~

Severity Override Guidance: 

Check the version of the operating system with the following command:

# cat /etc/redhat-release

Red Hat Enterprise Linux Server release 7.2 (Maipo)
Current End of Life for RHEL 7 is June 30, 2024.

If the release is not supported by the vendor, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-020310 - The root account must be the only account having unrestricted access to the system.
----------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

If an account other than root also has a User Identifier (UID) of “0”, it has root authority, giving that account unrestricted access to the entire operating system. Multiple accounts with a UID of “0” afford an opportunity for potential intruders to guess a password for a privileged account.

Check
~~~~~

Check the system for duplicate UID “0” assignments with the following command:

# awk -F: '$3 == 0 {print $1}' /etc/passwd

If any accounts other than root have a UID of “0”, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-021280 - The operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000396-GPOS-00176, SRG-OS-000478-GPOS-00223

Check
~~~~~

Verify the operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions.

Check to see if the dracut-fips package is installed with the following command:

# yum list installed | grep dracut-fips

dracut-fips-033-360.el7_2.x86_64.rpm

If the dracut-fips package is installed, check to see if the kernel command line is configured to use FIPS mode with the following command:

Note: GRUB 2 reads its configuration from the “/boot/grub2/grub.cfg” file on traditional BIOS-based machines and from the “/boot/efi/EFI/redhat/grub.cfg” file on UEFI machines.

#grep fips /boot/grub2/grub.cfg
/vmlinuz-3.8.0-0.40.el7.x86_64 root=/dev/mapper/rhel-root ro rd.md=0 rd.dm=0 rd.lvm.lv=rhel/swap crashkernel=auto rd.luks=0 vconsole.keymap=us rd.lvm.lv=rhel/root rhgb fips=1 quiet

If the kernel command line is configured to use FIPS mode, check to see if the system is in FIPS mode with the following command:

# cat /proc/sys/crypto/fips_enabled 1

If the dracut-fips package is not installed, the kernel command line does not have a fips entry, or the system has a value of “0” for fips_enabled in /proc/sys/crypto, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: NEW

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000068, CCI-002450


----




RHEL-07-021910 - The telnet-server package must not be installed.
-----------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.

Check
~~~~~

Verify the operating system is configured to disable non-essential capabilities. The most secure way of ensuring a non-essential capability is disabled is to not have the capability installed.

The telnet service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session.

If a privileged user were to log on using this service, the privileged user password could be compromised. 

Check to see if the telnet-server package is installed with the following command:

# yum list installed | grep telnet-server

If the telnet-server package is installed, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000381


----




RHEL-07-030010 - Auditing must be configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events.

These audit records must also identify individual identities of group account users.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.

Satisfies: SRG-OS-000038-GPOS-00016, SRG-OS-000039-GPOS-00017, SRG-OS-000042-GPOS-00021, SRG-OS-000254-GPOS-00095, SRG-OS-000255-GPOS-00096

Check
~~~~~

Verify the operating system produces audit records containing information to establish when (date and time) the events occurred.

Check to see if auditing is active by issuing the following command:

# systemctl is-active auditd.service
Active: active (running) since Tue 2015-01-27 19:41:23 EST; 22h ago

If the auditd status is not active, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000131, CCI-000126


----




RHEL-07-030810 - The system must use a DoD-approved virus scan program.
-----------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.  

The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.

If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.

Check
~~~~~

Verify the system is using a DoD-approved virus scan program.

Check for the presence of “McAfee VirusScan Enterprise for Linux” with the following command:

# systemctl status nails
nails - service for McAfee VirusScan Enterprise for Linux 
>  Loaded: loaded /opt/NAI/package/McAfeeVSEForLinux/McAfeeVSEForLinux-2.0.2.<build_number>; enabled)
>  Active: active (running) since Mon 2015-09-27 04:11:22 UTC;21 min ago

If the “nails” service is not active, check for the presence of “clamav” on the system with the following command:

# systemctl status clamav-daemon.socket
 systemctl status clamav-daemon.socket
  clamav-daemon.socket - Socket for Clam AntiVirus userspace daemon
     Loaded: loaded (/lib/systemd/system/clamav-daemon.socket; enabled)
     Active: active (running) since Mon 2015-01-12 09:32:59 UTC; 7min ago

If neither of these applications are loaded and active, ask the System Administrator (SA) if there is an antivirus package installed and active on the system. If no antivirus scan program is active on the system, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-001668


----




RHEL-07-040330 - There must be no .shosts files on the system.
--------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

The .shosts files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.

Check
~~~~~

Verify there are no .shosts files on the system.

Check the system for the existence of these files with the following command:

# find / -name '*.shosts’

If any .shosts files are found on the system, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-040331 - There must be no shosts.equiv files on the system.
-------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

The shosts.equiv files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.

Check
~~~~~

Verify there are no shosts.equiv files on the system.

Check the system for the existence of these files with the following command:

# find / -name shosts.equiv

If any shosts.equiv files are found on the system, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-040490 - A File Transfer Protocol (FTP) server package must not be installed unless needed.
---------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.

Check
~~~~~

Verify a lightweight FTP server has not been installed on the system.

Check to see if a lightweight FTP server has been installed with the following commands:

# yum list installed | grep lftpd
 lftp-4.4.8-7.el7.x86_64.rpm

An alternate method of determining if a lightweight FTP server is active on the server is to use the following command:

# netstat -a | grep 21

If “lftpd” is installed, or if an application is listening on port 21, and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-040500 - The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for operational support.
----------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Manager (ISSM), restricted to only authorized personnel, and have access control rules established.

Check
~~~~~

Verify a TFTP server has not been installed on the system.

Check to see if a TFTP server has been installed with the following command:

# yum list installed | grep tftp-server
tftp-server-0.49-9.el7.x86_64.rpm

An alternate method of determining if a TFTP server is active on the server is to use the following commands:

# netstat -a | grep 69
# netstat -a | grep 8099

If TFTP is installed and the requirement for TFTP is not documented with the ISSM, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000368, CCI-000318, CCI-001812, CCI-001813, CCI-001814


----




RHEL-07-040540 - Remote X connections for interactive users must be encrypted.
------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Open X displays allow an attacker to capture keystrokes and execute commands remotely.

Check
~~~~~

Verify remote X connections for interactive users are encrypted.

Check that remote X connections are encrypted with the following command:

# grep -i x11forwarding /etc/ssh/sshd_config
X11Fowarding yes

If the X11Forwarding keyword is set to "no", is missing, or is commented out, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-040580 - SNMP community strings must be changed from the default.
-------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Whether active or not, default Simple Network Management Protocol (SNMP) community strings must be changed to maintain security. If the service is running with the default authenticators, anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s). It is highly recommended that SNMP version 3 user authentication and message encryption be used in place of the version 2 community strings.

Check
~~~~~

Verify that a system using SNMP is not using default community strings.

Check to see if the “/etc/snmp/snmpd.conf” file exists with the following command:

# ls -al /etc/snmp/snmpd.conf
 -rw-------   1 root root      52640 Mar 12 11:08 snmpd.conf

If the file does not exist, this is Not Applicable.

If the file does exist, check for the default community strings with the following commands:

# grep public /etc/snmp/snmpd.conf
# grep private /etc/snmp/snmpd.conf

If either of these command returns any output, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-040590 - The SSH daemon must be configured to only use the SSHv2 protocol.
----------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.

Satisfies: SRG-OS-000074-GPOS-00042, SRG-OS-000480-GPOS-00227

Check
~~~~~

Verify the SSH daemon is configured to only use the SSHv2 protocol.

Check that the SSH daemon is configured to only use the SSHv2 protocol with the following command:

# grep -i protocol /etc/ssh/sshd_config
Protocol 2
#Protocol 1,2

If any protocol line other than "Protocol 2" is uncommented, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: None

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000197, CCI-000366


