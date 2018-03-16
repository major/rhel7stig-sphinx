
High
====




V-71849 - The file permissions, ownership, and group membership of system files and commands must match the vendor values. - RHEL-07-010010
-------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Discretionary access control is weakened if a user or group has access permissions to system files and directories greater than the default.

Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000278-GPOS-00108

Fix
~~~

Run the following command to determine which package owns the file:

# rpm -qf <filename>

Reset the permissions of files within a package with the following command:

#rpm --setperms <packagename>

Reset the user and group ownership of files within a package with the following command:

#rpm --setugids <packagename>

Check
~~~~~

Verify the file permissions, ownership, and group membership of system files and commands match the vendor values.

Check the file permissions, ownership, and group membership of system files and commands with the following command:

# rpm -Va | grep '^.M'

If there is any output from the command indicating that the ownership or group of a system file or command, or a system file, has permissions less restrictive than the default, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-001494, CCI-001496


----




V-71855 - The cryptographic hash of system files and commands must match vendor values. - RHEL-07-010020
--------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Without cryptographic integrity protections, system command and files can be altered by unauthorized users without detection.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash.

Fix
~~~

Run the following command to determine which package owns the file:

# rpm -qf <filename>

The package can be reinstalled from a yum repository using the command:

# sudo yum reinstall <packagename>

Alternatively, the package can be reinstalled from trusted media using the command:

# sudo rpm -Uvh <packagename>

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000663


----




V-71937 - The system must not have accounts configured with blank or null passwords. - RHEL-07-010290
-----------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

Fix
~~~

If an account is configured for password authentication but does not have an assigned password, it may be possible to log on to the account without authenticating.

Remove any instances of the "nullok" option in "/etc/pam.d/system-auth-ac" to prevent logons with empty passwords.

Note: Any updates made to "/etc/pam.d/system-auth-ac" may be overwritten by the "authconfig" program. The "authconfig" program should not be used.

Check
~~~~~

To verify that null passwords cannot be used, run the following command: 

# grep nullok /etc/pam.d/system-auth-ac

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




V-71939 - The SSH daemon must not allow authentication using an empty password. - RHEL-07-010300
------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.

Fix
~~~

To explicitly disallow remote logon from accounts with empty passwords, add or correct the following line in "/etc/ssh/sshd_config":

PermitEmptyPasswords no

The SSH service must be restarted for changes to take effect.  Any accounts with empty passwords should be disabled immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords.

Check
~~~~~

To determine how the SSH daemon's "PermitEmptyPasswords" option is set, run the following command:

# grep -i PermitEmptyPasswords /etc/ssh/sshd_config
PermitEmptyPasswords no

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000766


----




V-71953 - The operating system must not allow an unattended or automatic logon to the system via a graphical user interface. - RHEL-07-010440
---------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Failure to restrict system access to authenticated users negatively impacts operating system security.

Fix
~~~

Configure the operating system to not allow an unattended or automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Add or edit the line for the "AutomaticLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf" file to "false":

[daemon]
AutomaticLoginEnable=false

Check
~~~~~

Verify the operating system does not allow an unattended or automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check for the value of the "AutomaticLoginEnable" in the "/etc/gdm/custom.conf" file with the following command:

# grep -i automaticloginenable /etc/gdm/custom.conf
AutomaticLoginEnable=false

If the value of "AutomaticLoginEnable" is not set to "false", this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




V-71955 - The operating system must not allow an unrestricted logon to the system. - RHEL-07-010450
---------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Failure to restrict system access to authenticated users negatively impacts operating system security.

Fix
~~~

Configure the operating system to not allow an unrestricted account to log on to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Add or edit the line for the "TimedLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf" file to "false":

[daemon]
TimedLoginEnable=false

Check
~~~~~

Verify the operating system does not allow an unrestricted logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check for the value of the "TimedLoginEnable" parameter in "/etc/gdm/custom.conf" file with the following command:

# grep -i timedloginenable /etc/gdm/custom.conf
TimedLoginEnable=false

If the value of "TimedLoginEnable" is not set to "false", this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




V-71961 - Systems with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes. - RHEL-07-010480
-----------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

Fix
~~~

Configure the system to encrypt the boot password for root.

Generate an encrypted grub2 password for root with the following command:

Note: The hash generated is an example.

# grub2-mkpasswd-pbkdf2

Enter Password:
Reenter Password:
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45

Edit "/etc/grub.d/40_custom" and add the following lines below the comments:

# vi /etc/grub.d/40_custom

set superusers="root"

password_pbkdf2 root {hash from grub2-mkpasswd-pbkdf2 command}

Generate a new "grub.conf" file with the new password with the following commands:

# grub2-mkconfig --output=/tmp/grub2.cfg
# mv /tmp/grub2.cfg /boot/grub2/grub.cfg


Check
~~~~~

For systems that use UEFI, this is Not Applicable.

Check to see if an encrypted root password is set. On systems that use a BIOS, use the following command:

# grep -i ^password_pbkdf2 /boot/grub2/grub.cfg

password_pbkdf2 [superusers-account] [password-hash]

If the root password entry does not begin with "password_pbkdf2", this is a finding.

If the "superusers-account" is not set to "root", this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000213


----




V-71963 - Systems using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes. - RHEL-07-010490
----------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

Fix
~~~

Configure the system to encrypt the boot password for root.

Generate an encrypted grub2 password for root with the following command:

Note: The hash generated is an example.

# grub2-mkpasswd-pbkdf2

Enter Password:
Reenter Password:
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45

Edit "/etc/grub.d/40_custom" and add the following lines below the comments:

# vi /etc/grub.d/40_custom

set superusers="root"

password_pbkdf2 root {hash from grub2-mkpasswd-pbkdf2 command}

Generate a new "grub.conf" file with the new password with the following commands:

# grub2-mkconfig --output=/tmp/grub2.cfg
# mv /tmp/grub2.cfg /boot/efi/EFI/redhat/grub.cfg


Check
~~~~~

For systems that use BIOS, this is Not Applicable.

Check to see if an encrypted root password is set. On systems that use UEFI, use the following command:

# grep -i password /boot/efi/EFI/redhat/grub.cfg

password_pbkdf2 [superusers-account] [password-hash]

If the root password entry does not begin with "password_pbkdf2", this is a finding.

If the "superusers-account" is not set to "root", this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000213


----




V-71967 - The rsh-server package must not be installed. - RHEL-07-020000
------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

The rsh-server service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session and has very weak authentication.

If a privileged user were to log on using this service, the privileged user password could be compromised.

Fix
~~~

Configure the operating system to disable non-essential capabilities by removing the rsh-server package from the system with the following command:

# yum remove rsh-server

Check
~~~~~

Check to see if the rsh-server package is installed with the following command:

# yum list installed rsh-server

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000381


----




V-71969 - The ypserv package must not be installed. - RHEL-07-020010
--------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.

Fix
~~~

Configure the operating system to disable non-essential capabilities by removing the "ypserv" package from the system with the following command:

# yum remove ypserv

Check
~~~~~

The NIS service provides an unencrypted authentication service that does not provide for the confidentiality and integrity of user passwords or the remote session.

Check to see if the "ypserve" package is installed with the following command:

# yum list installed ypserv

If the "ypserv" package is installed, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000381


----




V-71977 - The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization. - RHEL-07-020050
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.

Fix
~~~

Configure the operating system to verify the signature of packages from a repository prior to install by setting the following option in the "/etc/yum.conf" file:

gpgcheck=1

Check
~~~~~

Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components from a repository without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.

Check that yum verifies the signature of packages from a repository prior to install with the following command:

# grep gpgcheck /etc/yum.conf
gpgcheck=1

If "gpgcheck" is not set to "1", or if options are missing or commented out, ask the System Administrator how the certificates for patches and other operating system components are verified. 

If there is no process to validate certificates that is approved by the organization, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-001749


----




V-71979 - The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization. - RHEL-07-020060
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.

Fix
~~~

Configure the operating system to verify the signature of local packages prior to install by setting the following option in the "/etc/yum.conf" file:

localpkg_gpgcheck=1

Check
~~~~~

Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.

Check that yum verifies the signature of local packages prior to install with the following command:

# grep localpkg_gpgcheck /etc/yum.conf
localpkg_gpgcheck=1

If "localpkg_gpgcheck" is not set to "1", or if options are missing or commented out, ask the System Administrator how the signatures of local packages and other operating system components are verified. 

If there is no process to validate the signatures of local packages that is approved by the organization, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-001749


----




V-71981 - The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of packages without verification of the repository metadata. - RHEL-07-020070
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved Certificate Authority.

Fix
~~~

Configure the operating system to verify the repository metadata by setting the following options in the "/etc/yum.conf" file:

repo_gpgcheck=1

Check
~~~~~

Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification of the repository metadata.

Check that yum verifies the package metadata prior to install with the following command:

# grep repo_gpgcheck /etc/yum.conf
repo_gpgcheck=1

If "repo_gpgcheck" is not set to "1", or if options are missing or commented out, ask the System Administrator how the metadata of local packages and other operating system components are verified. 

If there is no process to validate the metadata of packages that is approved by the organization, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-001749


----




V-71989 - The operating system must enable SELinux. - RHEL-07-020210
--------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

Fix
~~~

Configure the operating system to verify correct operation of all security functions.

Set the "SELinux" status and the "Enforcing" mode by modifying the "/etc/selinux/config" file to have the following line:

SELINUX=enforcing

A reboot is required for the changes to take effect.

Check
~~~~~

Verify the operating system verifies correct operation of all security functions.

Check if "SELinux" is active and in "Enforcing" mode with the following command:

# getenforce
Enforcing

If "SELinux" is not active and not in "Enforcing" mode, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-002165, CCI-002696


----




V-71991 - The operating system must enable the SELinux targeted policy. - RHEL-07-020220
----------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

Fix
~~~

Configure the operating system to verify correct operation of all security functions.

Set the "SELinuxtype" to the "targeted" policy by modifying the "/etc/selinux/config" file to have the following line:

SELINUXTYPE=targeted

A reboot is required for the changes to take effect.

Check
~~~~~

Verify the operating system verifies correct operation of all security functions.

Check if "SELinux" is active and is enforcing the targeted policy with the following command:

# sestatus

SELinux status:                 enabled

SELinuxfs mount:                /selinux

SELinux root directory:         /etc/selinux

Loaded policy name:             targeted

Current mode:                   enforcing

Mode from config file:          enforcing

Policy MLS status:              enabled

Policy deny_unknown status:     allowed

Max kernel policy version:      28


If the "Policy from config file" is not set to "targeted", or the "Loaded policy name" is not set to "targeted", this is a finding.


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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-002165, CCI-002696


----




V-71993 - The x86 Ctrl-Alt-Delete key sequence must be disabled. - RHEL-07-020230
---------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

Fix
~~~

Configure the system to disable the Ctrl-Alt_Delete sequence for the command line with the following command:

# systemctl mask ctrl-alt-del.target

If GNOME is active on the system, create a database to contain the system-wide setting (if it does not already exist) with the following command: 

# cat /etc/dconf/db/local.d/00-disable-CAD 

Add the setting to disable the Ctrl-Alt_Delete sequence for GNOME:

[org/gnome/settings-daemon/plugins/media-keys]
logout=’’

Check
~~~~~

Verify the operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

Check that the ctrl-alt-del.service is not active with the following command:

# systemctl status ctrl-alt-del.service
reboot.target - Reboot
   Loaded: loaded (/usr/lib/systemd/system/reboot.target; disabled)
   Active: inactive (dead)
     Docs: man:systemd.special(7)

If the ctrl-alt-del.service is active, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




V-71997 - The operating system must be a vendor supported release. - RHEL-07-020250
-----------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

Fix
~~~

Upgrade to a supported version of the operating system.

Check
~~~~~

Verify the version of the operating system is vendor supported.

Check the version of the operating system with the following command:

# cat /etc/redhat-release

Red Hat Enterprise Linux Server release 7.2 (Maipo)

Current End of Life for RHEL 7.2 is Q4 2020.

Current End of Life for RHEL 7.3 is 30 June 2024.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




V-72005 - The root account must be the only account having unrestricted access to the system. - RHEL-07-020310
--------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

If an account other than root also has a User Identifier (UID) of "0", it has root authority, giving that account unrestricted access to the entire operating system. Multiple accounts with a UID of "0" afford an opportunity for potential intruders to guess a password for a privileged account.

Fix
~~~

Change the UID of any account on the system, other than root, that has a UID of "0". 

If the account is associated with system commands or applications, the UID should be changed to one greater than "0" but less than "1000". Otherwise, assign a UID of greater than "1000" that has not already been assigned.

Check
~~~~~

Check the system for duplicate UID "0" assignments with the following command:

# awk -F: '$3 == 0 {print $1}' /etc/passwd

If any accounts other than root have a UID of "0", this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




V-72067 - The operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards. - RHEL-07-021350
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000185-GPOS-00079, SRG-OS-000396-GPOS-00176, SRG-OS-000405-GPOS-00184, SRG-OS-000478-GPOS-00223

Fix
~~~

Configure the operating system to implement DoD-approved encryption by installing the dracut-fips package.

To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the kernel command line during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

Configure the operating system to implement DoD-approved encryption by following the steps below: 

The fips=1 kernel option needs to be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users should also ensure that the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a non-unique key.

Install the dracut-fips package with the following command:

# yum install dracut-fips

Recreate the "initramfs" file with the following command:

Note: This command will overwrite the existing "initramfs" file.

# dracut -f

Modify the kernel command line of the current kernel in the "grub.cfg" file by adding the following option to the GRUB_CMDLINE_LINUX key in the "/etc/default/grub" file and then rebuild the "grub.cfg" file:

fips=1

Changes to "/etc/default/grub" require rebuilding the "grub.cfg" file as follows:

On BIOS-based machines, use the following command:

# grub2-mkconfig -o /boot/grub2/grub.cfg

On UEFI-based machines, use the following command:

# grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg

If /boot or /boot/efi reside on separate partitions, the kernel parameter boot=<partition of /boot or /boot/efi> must be added to the kernel command line. You can identify a partition by running the df /boot or df /boot/efi command:

# df /boot
Filesystem 1K-blocks Used Available Use% Mounted on
/dev/sda1 495844 53780 416464 12% /boot

To ensure the boot= configuration option will work even if device naming changes between boots, identify the universally unique identifier (UUID) of the partition with the following command:

# blkid /dev/sda1
/dev/sda1: UUID="05c000f1-a213-759e-c7a2-f11b7424c797" TYPE="ext4"

For the example above, append the following string to the kernel command line:

boot=UUID=05c000f1-a213-759e-c7a2-f11b7424c797

Reboot the system for the changes to take effect.


Check
~~~~~

Verify the operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions.

Check to see if the "dracut-fips" package is installed with the following command:

# yum list installed | grep dracut-fips

dracut-fips-033-360.el7_2.x86_64.rpm

If a "dracut-fips" package is installed, check to see if the kernel command line is configured to use FIPS mode with the following command:

Note: GRUB 2 reads its configuration from the "/boot/grub2/grub.cfg" file on traditional BIOS-based machines and from the "/boot/efi/EFI/redhat/grub.cfg" file on UEFI machines.

# grep fips /boot/grub2/grub.cfg
/vmlinuz-3.8.0-0.40.el7.x86_64 root=/dev/mapper/rhel-root ro rd.md=0 rd.dm=0 rd.lvm.lv=rhel/swap crashkernel=auto rd.luks=0 vconsole.keymap=us rd.lvm.lv=rhel/root rhgb fips=1 quiet

If the kernel command line is configured to use FIPS mode, check to see if the system is in FIPS mode with the following command:

# cat /proc/sys/crypto/fips_enabled 
1

If a "dracut-fips" package is not installed, the kernel command line does not have a fips entry, or the system has a value of "0" for "fips_enabled" in "/proc/sys/crypto", this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000068, CCI-001199, CCI-002450, CCI-002476


----




V-72077 - The telnet-server package must not be installed. - RHEL-07-021710
---------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.

Fix
~~~

Configure the operating system to disable non-essential capabilities by removing the telnet-server package from the system with the following command:

# yum remove telnet-server

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000381


----




V-72079 - Auditing must be configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events.

These audit records must also identify individual identities of group account users. - RHEL-07-030000
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.

Satisfies: SRG-OS-000038-GPOS-00016, SRG-OS-000039-GPOS-00017, SRG-OS-000042-GPOS-00021, SRG-OS-000254-GPOS-00095, SRG-OS-000255-GPOS-00096

Fix
~~~

Configure the operating system to produce audit records containing information to establish when (date and time) the events occurred.

Enable the auditd service with the following command:

# systemctl start auditd.service

Check
~~~~~

Verify the operating system produces audit records containing information to establish when (date and time) the events occurred.

Check to see if auditing is active by issuing the following command:

# systemctl is-active auditd.service
Active: active (running) since Tue 2015-01-27 19:41:23 EST; 22h ago

If the "auditd" status is not active, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000126, CCI-000131


----




V-72213 - The system must use a virus scan program. - RHEL-07-032000
--------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.  

The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.

If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.

Fix
~~~

Install an antivirus solution on the system.

Check
~~~~~

Verify the system is using a virus scan program.

Check for the presence of "McAfee VirusScan Enterprise for Linux" with the following command:

# systemctl status nails
nails - service for McAfee VirusScan Enterprise for Linux 
>  Loaded: loaded /opt/NAI/package/McAfeeVSEForLinux/McAfeeVSEForLinux-2.0.2.<build_number>; enabled)
>  Active: active (running) since Mon 2015-09-27 04:11:22 UTC;21 min ago

If the "nails" service is not active, check for the presence of "clamav" on the system with the following command:

# systemctl status clamav-daemon.socket
 systemctl status clamav-daemon.socket
  clamav-daemon.socket - Socket for Clam AntiVirus userspace daemon
     Loaded: loaded (/lib/systemd/system/clamav-daemon.socket; enabled)
     Active: active (running) since Mon 2015-01-12 09:32:59 UTC; 7min ago

If neither of these applications are loaded and active, ask the System Administrator if there is an antivirus package installed and active on the system. 

If no antivirus scan program is active on the system, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-001668


----




V-72251 - The SSH daemon must be configured to only use the SSHv2 protocol. - RHEL-07-040390
--------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.

Satisfies: SRG-OS-000074-GPOS-00042, SRG-OS-000480-GPOS-00227

Fix
~~~

Remove all Protocol lines that reference version "1" in "/etc/ssh/sshd_config" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor). The "Protocol" line must be as follows:

Protocol 2

The SSH service must be restarted for changes to take effect.

Check
~~~~~

Check the version of the operating system with the following command:

# cat /etc/redhat-release

If the release is 7.4 or newer this requirement is Not Applicable.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000197, CCI-000366


----




V-72277 - There must be no .shosts files on the system. - RHEL-07-040540
------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

The .shosts files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.

Fix
~~~

Remove any found ".shosts" files from the system.

# rm /[path]/[to]/[file]/.shosts

Check
~~~~~

Verify there are no ".shosts" files on the system.

Check the system for the existence of these files with the following command:

# find / -name '*.shosts'

If any ".shosts" files are found on the system, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




V-72279 - There must be no shosts.equiv files on the system. - RHEL-07-040550
-----------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

The shosts.equiv files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.

Fix
~~~

Remove any found "shosts.equiv" files from the system.

# rm /[path]/[to]/[file]/shosts.equiv

Check
~~~~~

Verify there are no "shosts.equiv" files on the system.

Check the system for the existence of these files with the following command:

# find / -name shosts.equiv

If any "shosts.equiv" files are found on the system, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




V-72299 - A File Transfer Protocol (FTP) server package must not be installed unless needed. - RHEL-07-040690
-------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.

Fix
~~~

Document the "vsftpd" package with the ISSO as an operational requirement or remove it from the system with the following command:

# yum remove vsftpd


Check
~~~~~

Verify an FTP server has not been installed on the system.

Check to see if an FTP server has been installed with the following commands:

# yum list installed vsftpd

 vsftpd-3.0.2.el7.x86_64.rpm

If "vsftpd" is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.


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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




V-72301 - The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for operational support. - RHEL-07-040700
--------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established.

Fix
~~~

Remove the TFTP package from the system with the following command:

# yum remove tftp

Check
~~~~~

Verify a TFTP server has not been installed on the system.

Check to see if a TFTP server has been installed with the following command:

# yum list installed tftp-server
tftp-server-0.49-9.el7.x86_64.rpm

If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000318, CCI-000368, CCI-001812, CCI-001813, CCI-001814


----




V-72303 - Remote X connections for interactive users must be encrypted. - RHEL-07-040710
----------------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Open X displays allow an attacker to capture keystrokes and execute commands remotely.

Fix
~~~

Configure SSH to encrypt connections for interactive users.

Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "X11Forwarding" keyword and set its value to "yes" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

X11Forwarding yes

The SSH service must be restarted for changes to take effect.

Check
~~~~~

Verify remote X connections for interactive users are encrypted.

Check that remote X connections are encrypted with the following command:

# grep -i x11forwarding /etc/ssh/sshd_config

X11Forwarding yes

If the "X11Forwarding" keyword is set to "no", is missing, or is commented out, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




V-72313 - SNMP community strings must be changed from the default. - RHEL-07-040800
-----------------------------------------------------------------------------------

Severity
~~~~~~~~

High

Description
~~~~~~~~~~~

Whether active or not, default Simple Network Management Protocol (SNMP) community strings must be changed to maintain security. If the service is running with the default authenticators, anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s). It is highly recommended that SNMP version 3 user authentication and message encryption be used in place of the version 2 community strings.

Fix
~~~

If the "/etc/snmp/snmpd.conf" file exists, modify any lines that contain a community string value of "public" or "private" to another string value.

Check
~~~~~

Verify that a system using SNMP is not using default community strings.

Check to see if the "/etc/snmp/snmpd.conf" file exists with the following command:

# ls -al /etc/snmp/snmpd.conf
 -rw-------   1 root root      52640 Mar 12 11:08 snmpd.conf

If the file does not exist, this is Not Applicable.

If the file does exist, check for the default community strings with the following commands:

# grep public /etc/snmp/snmpd.conf
# grep private /etc/snmp/snmpd.conf

If either of these commands returns any output, this is a finding.

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

* SeverityOverrideGuidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


