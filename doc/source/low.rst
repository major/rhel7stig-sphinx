
Low
===




RHEL-07-010490 - Unnecessary default system accounts must be removed.
---------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

Default system accounts created at install time but never used by the system may inadvertently be configured for interactive logon. Vendor accounts and software may contain accounts that provide unauthorized access to the system. All accounts that are not used to support the system and application operation must be removed from the system.

Check
~~~~~

Verify unnecessary default system accounts have been removed.

Check the accounts that are on the system with the following command:

# more /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync

If unnecessary default accounts such as games or ftp exist in the “/etc/passwd” file, this is a finding.

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




RHEL-07-020200 - The operating system must remove all software components after updated versions have been installed.
---------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.

Check
~~~~~

Verify the operating system removes all software components after updated versions have been installed.

Check if yum is configured to remove unneeded packages with the following command:

# grep -i clean_requirements_on_remove /etc/yum.conf
clean_requirements_on_remove=1

If “clean_requirements_on_remove” is not set to “1”, “True”, or “yes”, or is not set in /etc/yum.conf, this is a finding.

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

* Control Correlation Identifiers: CCI-002617


----




RHEL-07-020300 - All Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file.
------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.

Check
~~~~~

Verify all GIDs referenced in the “/etc/passwd” file are defined in the “/etc/group” file.

Check that all referenced GIDs exist with the following command:

# pwck -r

If GIDs referenced in “/etc/passwd” file are returned as not defined in “/etc/group” file, this is a finding.

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

* Control Correlation Identifiers: CCI-000764


----




RHEL-07-021240 - A separate file system must be used for user home directories (such as /home or an equivalent).
----------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

Check
~~~~~

Verify that a separate file system/partition has been created for non-privileged local interactive user home directories.

Check the home directory assignment for all non-privileged users (those with a UID greater than 1000) on the system with the following command:

#cut -d: -f 1,3,6,7 /etc/passwd | egrep ":[1-4][0-9]{3}" | tr ":" "\t"

adamsj /home/adamsj /bin/bash
jacksonm /home/jacksonm /bin/bash
smithj /home/smithj /bin/bash

The output of the command will give the directory/partition that contains the home directories for the non-privileged users on the system (in this example, /home) and users’ shell. All accounts with a valid shell (such as /bin/bash) are considered interactive users.

Check that a file system/partition has been created for the non-privileged interactive users with the following command:

Note: The partition of /home is used in the example.

# grep /home /etc/fstab
UUID=333ada18    /home                   ext4    noatime,nobarrier,nodev  1 2

If a separate entry for the file system/partition that contains the non-privileged interactive users' home directories does not exist, or the file system/partition for the non-privileged interactive users is not /home, this is a finding.

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




RHEL-07-021250 - The system must use a separate file system for /var.
---------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

Check
~~~~~

Verify that a separate file system/partition has been created for /var.

Check that a file system/partition has been created for /var with the following command:

# grep /var /etc/fstab
UUID=c274f65f    /var                    ext4    noatime,nobarrier        1 2

If a separate entry for /var is not in use, this is a finding.

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




RHEL-07-021260 - The system must use /var/log/audit for the system audit data path.
-----------------------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

Check
~~~~~

Verify that a separate file system/partition has been created for the system audit data path.

Check that a file system/partition has been created for the system audit data path with the following command:

#grep /var/log/audit /etc/fstab
UUID=3645951a    /var/log/audit          ext4    defaults                 1 2

If a separate entry for /var/log/audit does not exist, ask the System Administrator (SA) if the system audit logs are being written to a different file system/partition on the system, then grep for that file system/partition. 

If a separate file system/partition does not exist for the system audit data path, this is a finding.

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




RHEL-07-021270 - The system must use a separate file system for /tmp (or equivalent).
-------------------------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

Check
~~~~~

Verify that a separate file system/partition has been created for /tmp.

Check that a file system/partition has been created for “/tmp” with the following command:

# grep /tmp /etc/fstab
UUID=7835718b    /tmp    ext4    nodev,nosetuid,noexec      1 2

If a separate entry for /tmp is not in use, this is a finding.

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




RHEL-07-021600 - The file integrity tool must be configured to verify Access Control Lists (ACLs).
--------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools.

Check
~~~~~

Verify the file integrity tool is configured to verify ACLs.

Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:

# yum list installed | grep aide

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.

Note: AIDE is highly configurable at install time. These commands assume the “aide.conf” file is under the “/etc directory”. 

Use the following command to determine if the file is in another location:

# find / -name aide.conf

Check the “aide.conf” file to determine if the “acl” rule has been added to the rule list being applied to the files and directories selection lists.

An example rule that includes the “acl” rule is below:

All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All            # apply the custom rule to the files in bin 
/sbin All          # apply the same custom rule to the files in sbin 

If the “acl” rule is not being used on all selection lines in the “/etc/aide.conf” file, or acls are not being checked by another file integrity tool, this is a finding.

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




RHEL-07-021610 - The file integrity tool must be configured to verify extended attributes.
------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications.

Check
~~~~~

Verify the file integrity tool is configured to verify extended attributes.

Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:

# yum list installed | grep aide

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.

If there is no application installed to perform integrity checks, this is a finding.

Note: AIDE is highly configurable at install time. These commands assume the “aide.conf” file is under the “/etc directory”.  

Use the following command to determine if the file is in another location:

# find / -name aide.conf

Check the “aide.conf” file to determine if the “xattrs” rule has been added to the rule list being applied to the files and directories selection lists.

An example rule that includes the “xattrs” rule follows:

All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All            # apply the custom rule to the files in bin 
/sbin All          # apply the same custom rule to the files in sbin 

If the "xattrs" rule is not being used on all selection lines in the “/etc/aide.conf” file, or extended attributes are not being checked by another file integrity tool, this is a finding.

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




RHEL-07-040010 - The operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.
-------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.

Check
~~~~~

Verify the operating system limits the number of concurrent sessions to ten for all accounts and/or account types by issuing the following command:

# grep "maxlogins" /etc/security/limits.conf
* hard maxlogins 10

This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.

If the maxlogins item is missing or the value is not set to 10 or less for all domains that have the maxlogins item assigned, this is a finding.

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

* Control Correlation Identifiers: CCI-000054


----




RHEL-07-040300 - The system must display the date and time of the last successful account logon upon logon.
-----------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.

Check
~~~~~

Verify that users are provided with feedback on when account accesses last occurred.

Check that “pam_lastlog” is used and not silent with the following command:

# grep pam_lastlog /etc/pam.d/postlogin

session     required      pam_lastlog.so showfailed silent

If “pam_lastlog” is missing from “/etc/pam.d/postlogin” file, or the silent option is present on the line check for the “PrintLastLog” keyword in the sshd daemon configuration file, this is a finding.

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




RHEL-07-040320 - For systems using DNS resolution, at least two name servers must be configured.
------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Low

Description
~~~~~~~~~~~

To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.

Check
~~~~~

Determine whether the system is using local or DNS name resolution with the following command:

# grep hosts /etc/nsswitch.conf
hosts:   files dns

If the dns entry is missing from the host’s line in the “/etc/nsswitch.conf” file, the “/etc/resolv.conf” file must be empty.

Verify the “/etc/resolv.conf” file is empty with the following command:

# l s -al /etc/resolv.conf
-rw-r--r--  1 root root        0 Aug 19 08:31 resolv.conf

If local host authentication is being used and the “/etc/resolv.conf” file is not empty, this is a finding.

If the dns entry is found on the host’s line of the “/etc/nsswitch.conf” file, verify the operating system is configured to use two or more name servers for DNS resolution.

Determine the name servers used by the system with the following command:

# grep nameserver /etc/resolv.conf
nameserver 192.168.1.2
nameserver 192.168.1.3

If less than two lines are returned that are not commented out, this is a finding.

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


