
Medium
======




RHEL-07-010030 - The operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.\n\nSystem use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.\n\nThe banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:\n\n"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."\n\nUse the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:\n\n"I\'ve read  consent to terms in IS user agreem\'t."\n\nSatisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007, SRG-OS-000228-GPOS-00088

Check
~~~~~

Verify the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a graphical user logon.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check to see if the operating system displays a banner at the logon screen with the following command:

# grep banner-message-enable /etc/dconf/db/local.d/*
banner-message-enable=true

If banner-message-enable is set to false or is missing, this is a finding.

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

* Control Correlation Identifiers: CCI-000048


----




RHEL-07-010031 - The operating system must display the approved Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.\n\nSystem use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.\n\nThe banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:\n\n"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."\n\nUse the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:\n\n"I\'ve read  consent to terms in IS user agreem\'t."\n\nSatisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007, SRG-OS-000228-GPOS-00088

Check
~~~~~

Verify the operating system displays the approved Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a graphical user logon.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check that the operating system displays the exact approved Standard Mandatory DoD Notice and Consent Banner text with the command:

# grep banner-message-text /etc/dconf/db/local.d/*
banner-message-text=
‘You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.’

If the banner does not match the approved Standard Mandatory DoD Notice and Consent Banner, this is a finding.

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

* Control Correlation Identifiers: CCI-000048


----




RHEL-07-010040 - The operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.\n\nSystem use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.\n\nThe banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:\n\n"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."\n\nUse the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:\n\n"I\'ve read  consent to terms in IS user agreem\'t."\n\nSatisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007

Check
~~~~~

Verify the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon.

Check to see if the operating system displays a banner at the command line logon screen with the following command:

# more /etc/issue

The command should return the following text:
“You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.”

If the operating system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

If the text in the /etc/issue file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

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

* Control Correlation Identifiers: CCI-000048


----




RHEL-07-010060 - The operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures.
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.\n\nThe session lock is implemented at the point where session activity can be determined.\n\nRegardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.\n\nSatisfies: SRG-OS-000028-GPOS-00009, SRG-OS-000030-GPOS-00011

Check
~~~~~

Verify the operating system enables a user's session lock until that user re-establishes access using established identification and authentication procedures. The screen program must be installed to lock sessions on the console.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Check to see if the screen lock is enabled with the following command:

# grep -i lock-enabled /etc/dconf/db/local.d/00-screensaver
lock-enabled=true

If the "lock-enabled" setting is missing or is not set to true, this is a finding.

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

* Control Correlation Identifiers: CCI-000056


----




RHEL-07-010070 - The operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.
---------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.\n\nThe session lock is implemented at the point where session activity can be determined and/or controlled.

Check
~~~~~

Verify the operating system initiates a screensaver after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Check to see if GNOME is configured to display a screensaver after a 15 minute delay with the following command:

# grep -i idle-delay /etc/dconf/db/local.d/*
idle-delay=uint32 900

If the "idle-delay" setting is missing or is not set to “900” or less, this is a finding.

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

* Control Correlation Identifiers: CCI-000057


----




RHEL-07-010074 - The operating system must initiate a session lock for graphical user interfaces when the screensaver is activated.
-----------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.\n\nThe session lock is implemented at the point where session activity can be determined and/or controlled.

Check
~~~~~

Verify the operating system initiates a session lock a for graphical user interfaces when the screensaver is activated. The screen program must be installed to lock sessions on the console.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

If GNOME is installed, check to see a session lock occurs when the screensaver is activated with the following command:

# grep -i lock-delay /etc/dconf/db/local.d/*
lock-delay=uint32 5

If the “lock-delay” setting is missing, or is not set, this is a finding.

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

* Control Correlation Identifiers: CCI-000057


----




RHEL-07-010071 - The operating system must initiate a session lock after a 15-minute period of inactivity for all connection types.
-----------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.\n\nThe session lock is implemented at the point where session activity can be determined and/or controlled.

Check
~~~~~

Verify the operating system prevents the user from overriding session lock after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.

If it is installed, GNOME must be configured to prevent users from overriding the system-wide session lock settings. Check for the session lock settings with the following commands:

# grep -i idle-delay /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/screensaver/idle-delay
/org/gnome/desktop/session/idle-delay

If the command does not return a result for the screensaver and session keywords, this is a finding.

# grep -i lock-delay /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/screensaver/lock-delay

If the command does not return a result, this is a finding.

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

* Control Correlation Identifiers: CCI-000057


----




RHEL-07-010072 - The operating system must have the screen package installed.
-----------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.\n\nThe screen package allows for a session lock to be implemented and configured.

Check
~~~~~

Verify the operating system has the screen package installed.

Check to see if the screen package is installed with the following command:

# yum list installed | grep screen
screen-4.3.1-3-x86_64.rpm

If is not installed, this is a finding.

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

* Control Correlation Identifiers: CCI-000057


----




RHEL-07-010073 - The operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces.
--------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.\n\nThe session lock is implemented at the point where session activity can be determined and/or controlled.

Check
~~~~~

Verify the operating system initiates a session lock after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.

If it is installed, GNOME must be configured to enforce a session lock after a 15-minute delay. Check for the session lock settings with the following commands:

# grep -i  idle_activation_enabled /etc/dconf/db/local.d/*
[org/gnome/desktop/screensaver]   idle-activation-enabled=true

If the idle-activation-enabled not set to “true”, this is a finding.

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

* Control Correlation Identifiers: CCI-000057


----




RHEL-07-010090 - When passwords are changed or new passwords are established, the new password must contain at least one upper-case character.
----------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.\n\nPassword complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Check
~~~~~

Note: The value to require a number of upper-case characters to be set is expressed as a negative number in /etc/security/pwquality.conf.

Check the value for "ucredit" in /etc/security/pwquality.conf with the following command:

# grep ucredit /etc/security/pwquality.conf 
ucredit = -1

If the value of "ucredit" is not set to a negative value, this is a finding.

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

* Control Correlation Identifiers: CCI-000192


----




RHEL-07-010100 - When passwords are changed or new passwords are established, the new password must contain at least one lower-case character.
----------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.\n\nPassword complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Check
~~~~~

Note: The value to require a number of lower-case characters to be set is expressed as a negative number in /etc/security/pwquality.conf.

Check the value for "lcredit" in /etc/security/pwquality.conf with the following command:

# grep lcredit /etc/security/pwquality.conf 
lcredit = -1 

If the value of "lcredit" is not set to a negative value, this is a finding.

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

* Control Correlation Identifiers: CCI-000193


----




RHEL-07-010110 - When passwords are changed or new passwords are assigned, the new password must contain at least one numeric character.
----------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.\n\nPassword complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Check
~~~~~

Note: The value to require a number of numeric characters to be set is expressed as a negative number in /etc/security/pwquality.conf.

Check the value for "dcredit" in /etc/security/pwquality.conf with the following command:

# grep dcredit /etc/security/pwquality.conf 
dcredit = -1 

If the value of “dcredit” is not set to a negative value, this is a finding.

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

* Control Correlation Identifiers: CCI-000194


----




RHEL-07-010120 - When passwords are changed or new passwords are assigned, the new password must contain at least one special character.
----------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.\n\nPassword complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Check
~~~~~

Verify the operating system enforces password complexity by requiring that at least one special character be used.

Note: The value to require a number of special characters to be set is expressed as a negative number in /etc/security/pwquality.conf.

Check the value for “ocredit” in /etc/security/pwquality.conf with the following command:

# grep ocredit /etc/security/pwquality.conf 
ocredit=-1

If the value of “ocredit” is not set to a negative value, this is a finding.

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

* Control Correlation Identifiers: CCI-001619


----




RHEL-07-010130 - When passwords are changed a minimum of eight of the total number of characters must be changed.
-----------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.\n\nPassword complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Check
~~~~~

The "difok" option sets the number of characters in a password that must not be present in the old password.

Check for the value of the difok option in /etc/security/pwquality.conf with the following command:

# grep difok /etc/security/pwquality.conf 
difok = 8

If the value of “difok” is set to less than 8, this is a finding.

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

* Control Correlation Identifiers: CCI-000195


----




RHEL-07-010140 - When passwords are changed a minimum of four character classes must be changed.
------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.\n\nPassword complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Check
~~~~~

The "minclass" option sets the minimum number of required classes of characters for the new password (digits, uppercase, lowercase, others).

Check for the value of the “minclass” option in /etc/security/pwquality.conf with the following command:

# grep minclass /etc/security/pwquality.conf 
minclass = 4

If the value of “minclass” is set to less than 4, this is a finding.

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

* Control Correlation Identifiers: CCI-000195


----




RHEL-07-010150 - When passwords are changed the number of repeating consecutive characters must not be more than four characters.
---------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.\n\nPassword complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Check
~~~~~

The "maxrepeat" option sets the maximum number of allowed same consecutive characters in a new password.

Check for the value of the “maxrepeat” option in /etc/security/pwquality.conf with the following command:

# grep maxrepeat /etc/security/pwquality.conf 
maxrepeat = 2

If the value of “maxrepeat” is set to more than 2, this is a finding.

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

* Control Correlation Identifiers: CCI-000195


----




RHEL-07-010160 - When passwords are changed the number of repeating characters of the same character class must not be more than four characters.
-------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.\n\nPassword complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Check
~~~~~

The "maxclassrepeat" option sets the maximum number of allowed same consecutive characters in the same class in the new password.

Check for the value of the maxclassrepeat option in /etc/security/pwquality.conf with the following command:

# grep maxclassrepeat /etc/security/pwquality.conf 
maxclassrepeat = 4

If the value of “maxclassrepeat” is set to more than 4, this is a finding.

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

* Control Correlation Identifiers: CCI-000195


----




RHEL-07-010170 - The PAM system service must be configured to store only encrypted representations of passwords.
----------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.

Check
~~~~~

Verify the PAM system service is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512.

Check that the system is configured to create SHA512 hashed passwords with the following command:

# grep password /etc/pam.d/system-auth
password sufficient pam_unix.so sha512

If the /etc/pam.d/system-auth configuration files allow for password hashes other than SHA512 to be used, this is a finding.

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

* Control Correlation Identifiers: CCI-000196


----




RHEL-07-010180 - The shadow file must be configured to store only encrypted representations of passwords.
---------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.

Check
~~~~~

Verify the system's shadow file is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512.

Check that the system is configured to create SHA512 hashed passwords with the following command:

# grep -i encrypt /etc/login.defs
ENCRYPT_METHOD SHA512

If the /etc/login.defs configuration file does not exist or allows for password hashes other than SHA512 to be used, this is a finding.

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

* Control Correlation Identifiers: CCI-000196


----




RHEL-07-010190 - User and group account administration utilities must be configured to store only encrypted representations of passwords.
-----------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.

Check
~~~~~

Verify the user and group account administration utilities are configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512.

Check that the system is configured to create SHA512 hashed passwords with the following command:

# cat /etc/libuser.conf | grep -i sha512
[defaults]

crypt_style = sha512

If the "crypt_style" variable is not set to "sha512", is not in the defaults section, or does not exist, this is a finding.

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

* Control Correlation Identifiers: CCI-000196


----




RHEL-07-010200 - Passwords for new users must be restricted to a 24 hours/1 day minimum lifetime.
-------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

Check
~~~~~

Verify the operating system enforces 24 hours/1 day as the minimum password lifetime for new user accounts.

Check for the value of “PASS_MIN_DAYS” in /etc/login.defs with the following command: 

# grep -i pass_min_days /etc/login.defs
PASS_MIN_DAYS     1

If the “PASS_MIN_DAYS” parameter value is not “1” or greater, or is commented out, this is a finding.

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

* Control Correlation Identifiers: CCI-000198


----




RHEL-07-010210 - Passwords must be restricted to a 24 hours/1 day minimum lifetime.
-----------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

Check
~~~~~

Check whether the minimum time period between password changes for each user account is one day or greater.

# awk -F: '$4 < 1 {print $1}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.

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

* Control Correlation Identifiers: CCI-000198


----




RHEL-07-010220 - Passwords for new users must be restricted to a 60-day maximum lifetime.
-----------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.

Check
~~~~~

Verify the operating system enforces a 60-day maximum password lifetime restriction for new user accounts.

Check for the value of “PASS_MAX_DAYS” in /etc/login.defs with the following command:

# grep -i pass_max_days /etc/login.defs
PASS_MAX_DAYS     60

If the “PASS_MAX_DAYS” parameter value is not 60 or less, or is commented out, this is a finding.

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

* Control Correlation Identifiers: CCI-000199


----




RHEL-07-010230 - Existing passwords must be restricted to a 60-day maximum lifetime.
------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.

Check
~~~~~

Check whether the maximum time period for existing passwords is restricted to 60 days.

# awk -F: '$5 > 60 {print $1}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.

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

* Control Correlation Identifiers: CCI-000199


----




RHEL-07-010240 - Passwords must be prohibited from reuse for a minimum of five generations.
-------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.

Check
~~~~~

Verify the operating system prohibits password reuse for a minimum of five generations.

Check for the value of the “remember” argument in /etc/pam.d/system-auth with the following command:

# grep -i remember /etc/pam.d/system-auth
password sufficient pam_unix.so use_authtok sha512 shadow remember=5

If the line containing the pam_unix.so line does not have the “remember” module argument set, or the value of the “remember” module argument is set to less than “5”, this is a finding.

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

* Control Correlation Identifiers: CCI-000200


----




RHEL-07-010250 - Passwords must be a minimum of 15 characters in length.
------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.\n\nPassword complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

Check
~~~~~

Verify the operating system enforces a minimum 15-character password length. The “minlen” option sets the minimum number of characters in a new password.

Check for the value of the “minlen” option in /etc/security/pwquality.conf with the following command:

# grep minlen /etc/security/pwquality.conf
minlen = 15

If the command does not return a “minlen” value of 15 or greater, this is a finding.

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

* Control Correlation Identifiers: CCI-000205


----




RHEL-07-010280 - The operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.
-----------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.\n\nOperating systems need to track periods of inactivity and disable application identifiers after zero days of inactivity.

Check
~~~~~

Verify the operating system disables account identifiers (individuals, groups, roles, and devices) after the password expires with the following command:

# grep -i inactive /etc/default/useradd
INACTIVE=0

If the value is not set to “0”, is commented out, or is not defined, this is a finding.

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

* Control Correlation Identifiers: CCI-000795


----




RHEL-07-010371 - If three unsuccessful logon attempts within 15 minutes occur the associated account must be locked.
--------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.\n\nSatisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005

Check
~~~~~

Verify the operating system automatically locks an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.

Check that the system locks the account after three unsuccessful logon attempts within a period of 15 minutes with the following command:

# grep pam_faillock.so /etc/pam.d/password-auth
auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900

If the “fail_interval” setting is greater than 900 on both lines with the pam_faillock.so module name or is missing from a line, this is a finding.

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

* Control Correlation Identifiers: CCI-002238


----




RHEL-07-010372 - Accounts subject to three unsuccessful login attempts within 15 minutes must be locked for the maximum configurable period.
--------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.\n\nSatisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005

Check
~~~~~

Verify the operating system automatically locks an account for the maximum period for which the system can be configured.

Check that the system locks an account for the maximum period after three unsuccessful logon attempts within a period of 15 minutes with the following command:

# grep pam_faillock.so /etc/pam.d/password-auth
auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=604800
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=604800

If the “unlock_time” setting is greater than 604800 on both lines with the pam_faillock.so module name or is missing from a line, this is a finding.

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

* Control Correlation Identifiers: CCI-002238


----




RHEL-07-010373 - If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked.
-------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.\n\nSatisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005

Check
~~~~~

Verify the operating system automatically locks the root account until it is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.

# grep pam_faillock.so /etc/pam.d/password-auth
auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900
auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900

If the “even_deny_root” setting is not defined on both lines with the pam_faillock.so module name, this is a finding.

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

* Control Correlation Identifiers: CCI-002238


----




RHEL-07-010380 - Users must provide a password for privilege escalation.
------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without re-authentication, users may access resources or perform tasks for which they do not have authorization. \n\nWhen operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.\n\nSatisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158

Check
~~~~~

Verify the operating system requires users to supply a password for privilege escalation.

Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command:

# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

If any line is found with a "NOPASSWD" tag, this is a finding.

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

* Control Correlation Identifiers: CCI-002038


----




RHEL-07-010381 - Users must re-authenticate for privilege escalation.
---------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without re-authentication, users may access resources or perform tasks for which they do not have authorization. \n\nWhen operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.\n\nSatisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158

Check
~~~~~

Verify the operating system requires users to reauthenticate for privilege escalation.

Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command:

# grep -i authenticate /etc/sudoers /etc/sudoers.d/*

If any line is found with a "!authenticate" tag, this is a finding.

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

* Control Correlation Identifiers: CCI-002038


----




RHEL-07-010400 - The operating system must prohibit the use of cached nss authenticators after one day.
-------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If cached authentication information is out of date, the validity of the authentication information may be questionable.

Check
~~~~~

Verify the operating system prohibits the use of cached nss authenticators after one day.

Check to see if the “sssd” service is active with the following command:

# systemctl status sssd.service

If the service is active, the command will return:

sssd.service - System Security Services Daemon
   Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled)
   Active: active (running) since Thu 2014-09-25 10:46:43 CEST; 5s ago

If the service is not active, this is a finding.

Check the services option for the active services of each domain configured with the following command:

# grep services /etc/sssd/sssd.conf

The command will return one line for each domain. In the example:

services = nss, pam
services = nss, pam

There are two services lines as the “nss” and “pam” services are being used by two domains (ldap and local).

If nss is an active service, check the memcache_timeout option with the following command:

# grep -i memcache_timeout /etc/sssd/sssd.conf
memcache_timeout = 86400

If the “memcache_timeout” is set to a value greater than “86400”, is commented out, or is missing, this is a finding.

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

* Control Correlation Identifiers: CCI-002007


----




RHEL-07-010401 - The operating system must prohibit the use of cached PAM authenticators after one day.
-------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If cached authentication information is out of date, the validity of the authentication information may be questionable.

Check
~~~~~

Verify the operating system prohibits the use of cached PAM authenticators after one day.

Check to see if the “sssd” service is active with the following command:

# systemctl status sssd.service

If the service is active, the command will return:

sssd.service - System Security Services Daemon
   Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled)
   Active: active (running) since Thu 2014-09-25 10:46:43 CEST; 5s ago

If the service is not active, this is a finding.

Check the services option for the active services of each domain configured with the following command:

# grep services /etc/sssd/sssd.conf

The command will return one line for each domain. In the example:

services = nss, pam
services = nss, pam

There are two services lines as the “nss” and “pam” services are being used by two domains (ldap and local).

If “pam” is an active service, check the “offline_credentials_expiration” option with the following command:

# grep -i offline_credentials_expiration /etc/sssd/sssd.conf 
offline_credentials_expiration = 1

If “pam” is not an active service, this requirement is Not Applicable.

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

* Control Correlation Identifiers: CCI-002007


----




RHEL-07-010402 - The operating system must prohibit the use of cached SSH authenticators after one day.
-------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If cached authentication information is out of date, the validity of the authentication information may be questionable.

Check
~~~~~

Verify the operating system prohibits the use of cached SSH authenticators after one day.

Check to see if the “sssd” service is active with the following command:

# systemctl status sssd.service

If the service is active, the command will return:

sssd.service - System Security Services Daemon
   Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled)
   Active: active (running) since Thu 2014-09-25 10:46:43 CEST; 5s ago

If the service is not active, this is a finding.

Check the services option for the active services of each domain configured with the following command:

# grep services /etc/sssd/sssd.conf

The command will return one line for each domain. In the example:

services = nss, pam
services = nss, pam

There are two services lines as the “nss” and “pam” services are being used by two domains (ldap and local).

If “pam” is an active service, check the “offline_credentials_expiration” option with the following command:

# grep -i offline_credentials_expiration /etc/sssd/sssd.conf 
offline_credentials_expiration = 1

If “offline_credentials_expiration” is set to a value greater than “1”, is commented out, or is missing, this is a finding.

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

* Control Correlation Identifiers: CCI-002007


----




RHEL-07-010420 - The delay between logon prompts following a failed console logon attempt must be at least four seconds.
------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.\n\nConfiguration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.

Check
~~~~~

Verify the operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt.

Check the value of the fail_delay parameter in “/etc/login.defs” file with the following command:

# grep -i fail_delay /etc/login.defs
FAIL_DELAY 4

If the value of “FAIL_DELAY” is not set to “4” or greater, this is a finding.

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




RHEL-07-010441 - The operating system must not allow users to override SSH environment variables.
-------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Failure to restrict system access to authenticated users negatively impacts operating system security.

Check
~~~~~

Verify the operating system does not allow users to override environment variables to the SSH daemon.

Check for the value of the PermitUserEnvironment keyword with the following command:

# grep -i permituserenvironment /etc/ssh/sshd_config
PermitUserEnvironment no

If the “PermitUserEnvironment” keyword is not set to “no”, is missing, or is commented out, this is a finding.

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




RHEL-07-010442 - The operating system must not allow a non-certificate trusted host SSH logon to the system.
------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Failure to restrict system access to authenticated users negatively impacts operating system security.

Check
~~~~~

Verify the operating system does not allow a non-certificate trusted host SSH logon to the system.

Check for the value of the HostbasedAuthentication keyword with the following command:

# grep -i hostbasedauthentication /etc/ssh/sshd_config
HostbasedAuthentication no

If the “HostbasedAuthentication” keyword is not set to “no”, is missing, or is commented out, this is a finding.

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




RHEL-07-010500 - The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multi-factor authentication.
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.\n\nOrganizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following:\n\n1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; \n\nand\n\n2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.\n\nSatisfies: SRG-OS-000104-GPOS-00051, SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000109-GPOS-00056, SRG-OS-000108-GPOS-00055, SRG-OS-000108-GPOS-00057, SRG-OS-000108-GPOS-00058

Check
~~~~~

Verify the operating system requires multifactor authentication to uniquely identify organizational users using multi-factor authentication.

Check to see if smartcard authentication is enforced on the system:

# authconfig --test | grep -i smartcard

The entry for use only smartcard for login may be enabled, and the smartcard module and smartcard removal actions must not be blank.

If smartcard authentication is disabled or the smartcard and smartcard removal actions are blank, this is a finding.

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




RHEL-07-020090 - The operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.\n\nPrivileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.

Check
~~~~~

Verify the operating system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Get a list of authorized users (other than system administrator and guest accounts) for the system.

Check the list against the system by using the following command:

# semanage login -l | more
Login Name  SELinux User   MLS/MCS Range  Service
__default__  user_u    s0-s0:c0.c1023   *
root   unconfined_u   s0-s0:c0.c1023   *
system_u  system_u   s0-s0:c0.c1023   *
joe  staff_u   s0-s0:c0.c1023   *

All administrators must be mapped to the sysadm_u or staff_u users with the appropriate domains (sysadm_t and staff_t).

All authorized non-administrative users must be mapped to the user_u role or the appropriate domain (user_t).

If they are not mapped in this way, this is a finding.

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

* Control Correlation Identifiers: CCI-002165, CCI-002235


----




RHEL-07-020130 - A file integrity tool must verify the baseline operating system configuration at least weekly.
---------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.\n\nDetecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

Check
~~~~~

Verify the operating system routinely checks that baseline configuration changes are not performed in an authorized manner.

Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed at least once per week.

Check for the presence of a cron job running daily or weekly on the system that executes AIDE daily to scan for changes to the system baseline. The command used in the example will use a daily occurrence.

Check the /etc/cron.daily subdirectory for a crontab file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:

# ls -al /etc/cron.* | grep aide
-rwxr-xr-x  1 root root        29 Nov  22  2015 aide

If the file integrity application is not executed on the system with the required frequency, this is a finding.

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

* Control Correlation Identifiers: CCI-001744


----




RHEL-07-020140 - Designated personnel must be notified if baseline configurations are changed in an unauthorized manner.
------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.\n\nDetecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

Check
~~~~~

Verify the operating system notifies designated personnel if baseline configurations are changed in an unauthorized manner.

Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed and notify specified individuals via email or an alert.

Check for the presence of a cron job running routinely on the system that executes AIDE to scan for changes to the system baseline. The commands used in the example will use a daily occurrence.

Check the /etc/cron.daily subdirectory for a crontab file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following commands:

# ls -al /etc/cron.daily | grep aide
-rwxr-xr-x  1 root root        32 Jul  1  2011 aide

AIDE does not have a configuration that will send a notification, so the cron job uses the mail application on the system to email the results of the file integrity run as in the following example:

# more /etc/cron.daily/aide
0 0 * * * /usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil

If the file integrity application does not notify designated personnel of changes, this is a finding.

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

* Control Correlation Identifiers: CCI-001744


----




RHEL-07-020160 - USB mass storage must be disabled.
---------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity.\n\nSatisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163, SRG-OS-000480-GPOS-00227

Check
~~~~~

If there is an HBSS with a Device Control Module and a Data Loss Prevention mechanism, this requirement is not applicable.

Verify the operating system disables the ability to use USB mass storage devices.

Check to see if USB mass storage is disabled with the following command:

#grep -i usb-storage /etc/modprobe.d/*

install usb-storage /bin/true

If the command does not return any output, and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

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

* Control Correlation Identifiers: CCI-000366, CCI-000778, CCI-001958


----




RHEL-07-020161 - File system automounter must be disabled unless required.
--------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.\n\nSatisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163, SRG-OS-000480-GPOS-00227

Check
~~~~~

Verify the operating system disables the ability to automount devices.

Check to see if automounter service is active with the following command:

# systemctl status autofs
autofs.service - Automounts filesystems on demand
   Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
   Active: inactive (dead)

If the “autofs” status is set to “active” and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

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

* Control Correlation Identifiers: CCI-000366, CCI-000778, CCI-001958


----




RHEL-07-020230 - The operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.

Check
~~~~~

Verify the operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Check for the value of the “UMASK” parameter in “/etc/login.defs” file with the following command:

Note: If the value of the “UMASK” parameter is set to “000” in “/etc/login.defs” file, the Severity is raised to a CAT I.

# grep -i umask /etc/login.defs
UMASK  077

If the value for the “UMASK” parameter is not “077”, or the “UMASK” parameter is missing or is commented out, this is a finding.

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




RHEL-07-020250 - System security patches and updates must be installed and up to date.
--------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced system administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.

Check
~~~~~

Verify the operating system security patches and updates are installed and up to date. Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO). 

Obtain the list of available package security updates from Red Hat. The URL for updates is https://rhn.redhat.com/errata/. It is important to note that updates provided by Red Hat may not be present on the system if the underlying packages are not installed.

Check that the available package security updates have been installed on the system with the following command:

# yum history list | more
Loaded plugins: langpacks, product-id, subscription-manager
ID     | Command line             | Date and time    | Action(s)      | Altered
-------------------------------------------------------------------------------
    70 | install aide             | 2016-05-05 10:58 | Install        |    1   
    69 | update -y                | 2016-05-04 14:34 | Update         |   18 EE
    68 | install vlc              | 2016-04-21 17:12 | Install        |   21   
    67 | update -y                | 2016-04-21 17:04 | Update         |    7 EE
    66 | update -y                | 2016-04-15 16:47 | E, I, U        |   84 EE

If package updates have not been performed on the system within the timeframe that the site/program documentation requires, this is a finding. 

Typical update frequency may be overridden by information assurance vulnerability alert (IAVA) notifications from CYBERCOM.

If the operating system is in non-compliance with the IAVM process, this is a finding.

Additional Data
~~~~~~~~~~~~~~~


* Documentable: false

* False Negatives: None

* False Positives: None

* IA Controls: None

* Mitigation Control: Control value is 30 days.

* Mitigations: None

* Potential Impacts: None

* Responsibility: None

* Security Override Guidance: None

* Third Party Tools: None

* Control Correlation Identifiers: CCI-000366


----




RHEL-07-020290 - The system must not have unnecessary accounts.
---------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Accounts providing no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.

Check
~~~~~

Verify all accounts on the system are assigned to an active system, application, or user account.

Obtain the list of authorized system accounts from the Information System Security Officer (ISSO).

Check the system accounts on the system with the following command:

# more /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin

Accounts such as “games” and “gopher” are not authorized accounts as they do not support authorized system functions. 

If the accounts on the system do not match the provided documentation, or accounts that do not support an authorized system function are present, this is a finding.

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




RHEL-07-020360 - All files and directories must have a valid owner.
-------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier \xe2\x80\x9cUID\xe2\x80\x9d as the UID of the un-owned files.

Check
~~~~~

Verify all files and directories on the system have a valid owner.

Check the owner of all files and directories with the following command:

# find / -fstype local -xdev -nouser

If any files on the system do not have an assigned owner, this is a finding.

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

* Control Correlation Identifiers: CCI-002165


----




RHEL-07-020370 - All files and directories must have a valid group owner.
-------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.

Check
~~~~~

Verify all files and directories on the system have a valid group.

Check the owner of all files and directories with the following command:

# find / -fstype local -xdev -nogroup

If any files on the system do not have an assigned group, this is a finding.

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

* Control Correlation Identifiers: CCI-002165


----




RHEL-07-020620 - All local interactive users must have a home directory assigned in the /etc/passwd file.
---------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.

Check
~~~~~

Verify local interactive users on the system have a home directory assigned.

Check for missing local interactive user home directories with the following command:

# pwck -r
user 'lp': directory '/var/spool/lpd' does not exist
user 'news': directory '/var/spool/news' does not exist
user 'uucp': directory '/var/spool/uucp' does not exist
user 'smithj': directory '/home/smithj' does not exist

Ask the System Administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"

If any interactive users do not have a home directory assigned, this is a finding.

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




RHEL-07-020630 - All local interactive user accounts, upon creation, must be assigned a home directory.
-------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.

Check
~~~~~

Verify all local interactive users on the system are assigned a home directory upon creation.

Check to see if the system is configured to create home directories for local interactive users with the following command:

# grep -i create_home /etc/login.defs
CREATE_HOME yes

If the value for “CREATE_HOME” parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.

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




RHEL-07-020640 - All local interactive user home directories defined in the /etc/passwd file must exist.
--------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon logon. This could create a Denial of Service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.

Check
~~~~~

Verify the assigned home directory of all local interactive users on the system exists.

Check the home directory assignment for all local interactive non-privileged users on the system with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep ":[1-9][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj

Note: This may miss interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check that all referenced home directories exist with the following command:

# pwck -r
user 'smithj': directory '/home/smithj' does not exist

If any home directories referenced in “/etc/passwd” are returned as not defined, this is a finding.

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




RHEL-07-020650 - All local interactive user home directories must have mode 0750 or less permissive.
----------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.

Check
~~~~~

Verify the assigned home directory of all local interactive users has a mode of “0750” or less permissive.

Check the home directory assignment for all non-privileged users on the system with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check the mode on all local interactive users’ home directories with the following command:

# ls -al <users home directory>
drwxr-x---  1 smithj users        860 Nov 28 06:43 smithj

If home directories referenced in “/etc/passwd” do not have a mode of “0750” or less permissive, this is a finding.

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




RHEL-07-020660 - All local interactive user home directories must be owned by their respective users.
-----------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If a local interactive user does not own their home directory, unauthorized users could access or modify the user's files, and the users may not be able to access their own files.

Check
~~~~~

Verify the assigned home directory of all local interactive users is owned by that user.

Check the home directory assignment for all non-privileged users on the system with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj

Note: This may miss local interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check the owner of all local interactive users home directories with the following command:

# ls -al <users home directory>
drwxr-x---  1 smithj users        860 Nov 28 06:43 smithj

If user home directory referenced in “/etc/passwd” is not owned by that user, this is a finding.

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




RHEL-07-020670 - All local interactive user home directories must be group-owned by the home directory owners primary group.
----------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If the Group Identifier (GID) of a local interactive user\xe2\x80\x99s home directory is not the same as the primary GID of the user, this would allow unauthorized access to the user\xe2\x80\x99s files, and users that share the same group may not be able to access files that they legitimately should.

Check
~~~~~

Verify the assigned home directory of all local interactive users is group-owned by that user’s primary GID.

Check the home directory assignment for all non-privileged users on the system with the following command:

# cut -d: -f 1,3,4 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj 250

# grep 250 /etc/group
users:x:250:smithj,jonesj,jacksons

Note: This may miss local interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check the group owner of all local interactive users’ home directories with the following command:

# ls -al <users home directory>
drwxr-x---  1 smithj users        860 Nov 28 06:43 smithj

If the user home directory referenced in “/etc/passwd” is not group-owned by that user’s primary GID, this is a finding.

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




RHEL-07-020680 - All files and directories contained in local interactive user home directories must be owned by the owner of the home directory.
-------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If local interactive users do not own the files in their directories, unauthorized users may be able to access them. Additionally, if files are not owned by the user, this could be an indication of system compromise.

Check
~~~~~

Verify all files and directories in a local interactive user’s home directory are owned by the user.

Check the owner of all files and directories in a local interactive user’s home directory with the following command:

# ls -lLR /<home directory path>/<users home directory>/
/home/smithj
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj smithj 231 Mar  5 17:06 file3

If any files are found with an owner different than the home directory user, this is a finding.

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




RHEL-07-020690 - All files and directories contained in local interactive user home directories must be group-owned by a group of which the home directory owner is a member.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If a local interactive user\xe2\x80\x99s files are group-owned by a group of which the user is not a member, unintended users may be able to access them.

Check
~~~~~

Verify all files and directories in a local interactive user home directory are group-owned by a group the user is a member of.

Check the group owner of all files and directories in a local interactive user’s home directory with the following command:

Note: The example will be for the user “smithj”, who has a home directory of “/home/smithj/home/smithj”.

# ls -lLR /<home directory>/<users home directory>/
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj sa        231 Mar  5 17:06 file3

If any files are found with an owner different than the group home directory user, check to see if the user is a member of that group with the following command:

# grep smithj /etc/group
sa:x:100:juan,shelley,bob,smithj 
smithj:x:521:smithj

If the user is not a member of a group that group owns file(s) in a local interactive user’s home directory, this is a finding.

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




RHEL-07-020700 - All files and directories contained in local interactive user home directories must have mode 0750 or less permissive.
---------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If a local interactive user files have excessive permissions, unintended users may be able to access or modify them.

Check
~~~~~

Verify all files and directories contained in a local interactive user home directory, excluding local initialization files, have a mode of “0750”.

Check the mode of all non-initialization files in a local interactive user home directory with the following command:

Files that begin with a “.” are excluded from this requirement.

Note: The example will be for the user “smithj”, who has a home directory of “/home/smithj/home/smithj”

# ls -lLR /<home directory>/<users home directory>/
-rwxr-x--- 1 smithj smithj  18 Mar  5 17:06 file1
-rwxr----- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r-x--- 1 smithj sa        231 Mar  5 17:06 file3

If any files are found with a mode more permissive than “0750”, this is a finding.

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




RHEL-07-020840 - All local initialization files for interactive users must be owned by the home directory user or root.
-----------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.

Check
~~~~~

Verify all local initialization files for interactive users are owned by the home directory user or root.

Check the owner on all local initialization files with the following command:

Note: The example will be for the “smithj” user, who has a home directory of “/home/smithj”.

# ls -al /home/smithj/.* | more
-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .bash_profile
-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login
-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .profile

If any file that sets a local interactive user’s environment variables to override the system is not owned by the home directory owner or root, this is a finding.

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




RHEL-07-020850 - Local initialization files for local interactive users must be group-owned by the users primary group or root.
-------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Local initialization files for interactive users are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.

Check
~~~~~

Verify the local initialization files of all local interactive users are group-owned by that user’s primary Group Identifier (GID).

Check the home directory assignment for all non-privileged users on the system with the following command:

Note: The example will be for the smithj user, who has a home directory of “/home/smithj” and a primary group of users.

# cut -d: -f 1,3,4 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj 250

# grep 250 /etc/group
users:x:250:smithj,jonesj,jacksons 

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check the group owner of all local interactive users’ initialization files with the following command:

# ls -al /home/smithj/.*
-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .profile
-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login
-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .something

If all local interactive users’ initialization files are not group-owned by that user’s primary GID, this is a finding.

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




RHEL-07-020860 - All local initialization files must have mode 0740 or less permissive.
---------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.

Check
~~~~~

Verify that all local initialization files have a mode of “0740” or less permissive.

Check the mode on all local initialization files with the following command:

Note: The example will be for the smithj user, who has a home directory of “/home/smithj”.

# ls -al /home/smithj/.* | more
-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .profile
-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login
-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .something

If any local initialization files have a mode more permissive than “0740”, this is a finding.

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




RHEL-07-020870 - All local interactive user initialization files executable search paths must contain only absolute paths.
--------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory (other than the user\xe2\x80\x99s home directory), executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. If deviations from the default system search path for the local interactive user are required, they must be documented with the Information System Security Officer (ISSO).

Check
~~~~~

Verify that all local interactive user initialization files path statements do not contain statements that will reference a working directory other than the users’ home directory.

Check the path statement for all local interactive user initialization files in the users' home directory with the following commands:

Note: The example will be for the smithj user, which has a home directory of “/home/smithj”.

# grep -i path /home/smithj/.*
/home/smithj/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin
/home/smithj/.bash_profile:export PATH

If any local interactive user initialization files have path statements that include directories outside of their home directory, this is a finding.

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




RHEL-07-020880 - Local initialization files must not execute world-writable programs.
-------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.

Check
~~~~~

Verify that local initialization files do not execute world-writable programs.

Check the system for world-writable files with the following command:
# find / -perm -002 -type f -exec ls -ld {} \; | more

For all files listed, check for their presence in the local initialization files with the following commands:

Note: The example will be for a system that is configured to create users’ home directories in the /home directory.

# grep <file> /home/*/.*

If any local initialization files are found to reference world-writable files, this is a finding.

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




RHEL-07-020940 - All system device files must be correctly labeled to prevent unauthorized modification.
--------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If an unauthorized or modified device is allowed to exist on the system, there is the possibility the system may perform unintended or unauthorized operations.

Check
~~~~~

Verify that all system device files are correctly labeled to prevent unauthorized modification.

List all device files on the system that are incorrectly labeled with the following commands:

Note: Device files are normally found under “/dev”, but applications may place device files in other directories, necessitating a search of the entire system.

#find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"

#find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"

If there is output from either of these commands, this is a finding.

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

* Control Correlation Identifiers: CCI-000318, CCI-001812, CCI-001813, CCI-001814, CCI-000368


----




RHEL-07-021010 - Files systems that contain user home directories must be mounted to prevent files with the setuid and setgid bit set from being executed.
----------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

Check
~~~~~

Verify file systems that contain user home directories are mounted with the “nosetuid” option.

Find the file system(s) that contain the user home directories with the following command:

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under “/”) this is not a finding as the “nosetuid” option cannot be used on the “/” system.

# cut -d: -f 1,7 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"
smithj /home/smithj
thomasr /home/thomasr

Check the file systems that are mounted at boot time with the following command:

# more /etc/fstab

UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home   ext4   rw,relatime,discard,data=ordered,nosuid                                                                         0 2

If a file system found in “/etc/fstab” refers to the user home directory file system and it does not have the “nosetuid” option set, this is a finding.

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




RHEL-07-021011 - Files systems that are used with removable media must be mounted to prevent files with the setuid and setgid bit set from being executed.
----------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

Check
~~~~~

Verify file systems that are used for removable media are mounted with the “nosetuid” option.

Check the file systems that are mounted at boot time with the following command:

# more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222     /mnt/usbflash      vfat   noauto,owner,ro,nosuid                        0 0

If a file system found in “/etc/fstab” refers to removable media and it does not have the “nosetuid” option set, this is a finding.

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




RHEL-07-021012 - Files systems that are being imported via Network File System (NFS) must be mounted to prevent files with the setuid and setgid bit set from being executed.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

Check
~~~~~

Verify file systems that are being NFS exported are mounted with the “nosetuid” option.

Find the file system(s) that contain the directories being exported with the following command:

# more /etc/fstab | grep nfs

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d    /store           nfs           rw,nosuid                                                    0 0

If a file system found in “/etc/fstab” refers to NFS and it does not have the “nosuid” option set, this is a finding.

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




RHEL-07-021050 - All world-writable directories must be group-owned by root, sys, bin, or an application group.
---------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If a world-writable directory has the sticky bit set and is not group-owned by a privileged Group Identifier (GID), unauthorized users may be able to modify files created by others.\n\nThe only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.

Check
~~~~~

Verify all world-writable directories are group-owned by root, sys, bin, or an application group.

Check the system for world-writable directories with the following command:

# find / -perm -002 -type d -exec ls -lLd {} \;
drwxrwxrwt. 2 root root 40 Aug 26 13:07 /dev/mqueue
drwxrwxrwt. 2 root root 220 Aug 26 13:23 /dev/shm
drwxrwxrwt. 14 root root 4096 Aug 26 13:29 /tmp

If any world-writable directories are not owned by root, sys, bin, or an application group associated with the directory, this is a finding.

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




RHEL-07-021060 - The umask must be set to 077 for all local interactive user accounts.
--------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 700 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be \xe2\x80\x9c0\xe2\x80\x9d. This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.

Check
~~~~~

Verify that the default umask for all local interactive users is “077”.

Identify the locations of all local interactive user home directories by looking at the “/etc/passwd” file.

Check all local interactive user initialization files for interactive users with the following command:

Note: The example is for a system that is configured to create users home directories in the /home directory.

# grep -i umask /home/*/.*

If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than “077”, this is a finding.

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




RHEL-07-021160 - Cron logging must be implemented.
--------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.

Check
~~~~~

Verify that rsyslog is configured to log cron events.

Check the configuration of /etc/rsyslog.conf for the cron facility with the following command:

Note: If another logging package is used, substitute the utility configuration file for /etc/rsyslog.conf. 

# grep cron /etc/rsyslog.conf
cron.* /var/log/cron.log

If the command does not return a response, check for cron logging all facilities by inspecting the /etc/rsyslog.conf file:

# more /etc/rsyslog.conf

Look for the following entry:

*.* /var/log/messages

If rsyslog is not logging messages for the cron facility or all facilities, this is a finding.  

If the entry is in the “/etc/rsyslog.conf” file but is after the entry: *.*', this is a finding.

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




RHEL-07-021190 - If the cron.allow file exists it must be owned by root.
------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If the owner of the "cron.allow" file is not set to root, the possibility exists for an unauthorized user to view or to edit sensitive information.

Check
~~~~~

Verify that the "cron.allow" file is owned by root.

Check the owner of the "cron.allow" file with the following command:

# l s -al /etc/cron.allow
-rw------- 1 root root 6 Mar  5  2011 /etc/cron.allow

If the “cron.allow” file exists and has an owner other than root, this is a finding.

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




RHEL-07-021200 - If the cron.allow file exists it must be group-owned by root.
------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If the group owner of the \xe2\x80\x9ccron.allow\xe2\x80\x9d file is not set to root, sensitive information could be viewed or edited by unauthorized users.

Check
~~~~~

Verify that the “cron.allow” file is group-owned by root.

Check the group owner of the “cron.allow” file with the following command:

# ls -al /etc/cron.allow
-rw------- 1 root root 6 Mar  5  2011 /etc/cron.allow

If the “cron.allow” file exists and has a group owner other than root, this is a finding.

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




RHEL-07-021230 - Kernel core dumps must be disabled unless needed.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.

Check
~~~~~

Verify that kernel core dumps are disabled unless needed.

Check the status of the “kdump” service with the following command:

# systemctl status kdump.service
kdump.service - Crash recovery kernel arming
   Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled)
   Active: active (exited) since Wed 2015-08-26 13:08:09 EDT; 43min ago
 Main PID: 1130 (code=exited, status=0/SUCCESS)
kernel arming.

If the “kdump” service is active, ask the System Administrator (SA) if the use of the service is required and documented with the Information System Security Manager (ISSM).

If the service is active and is not documented, this is a finding.

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




RHEL-07-021620 - The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.
----------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

File integrity tools use cryptographic hashes for verifying file contents and directories have not been altered. These hashes must be FIPS 140-2 approved cryptographic hashes.

Check
~~~~~

Verify the file integrity tool is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.

Note: If RHEL-07-021280 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.

Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:

# yum list installed | grep aide

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.

Note: AIDE is highly configurable at install time. These commands assume the “aide.conf” file is under the “/etc directory”. 

Use the following command to determine if the file is in another location:

# find / -name aide.conf

Check the “aide.conf” file to determine if the “sha512” rule has been added to the rule list being applied to the files and directories selection lists.

An example rule that includes the sha512 rule follows:

All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All            # apply the custom rule to the files in bin 
/sbin All          # apply the same custom rule to the files in sbin 

If the “sha512” rule is not being used on all selection lines in the “/etc/aide.conf” file, or another file integrity tool is not using FIPS 140-2 approved cryptographic hashes for validating file contents and directories, this is a finding.

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




RHEL-07-021760 - The system must not allow removable media to be used as the boot loader unless approved.
---------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader. If removable media is designed to be used as the boot loader, the requirement must be documented with the Information System Security Officer (ISSO).

Check
~~~~~

Verify the system is not configured to use a boot loader on removable media.

Note: GRUB 2 reads its configuration from the “/boot/grub2/grub.cfg” file on traditional BIOS-based machines and from the “/boot/efi/EFI/redhat/grub.cfg” file on UEFI machines.

Check for the existence of alternate boot loader configuration files with the following command:

# find / -name grub.conf
/boot/grub2/grub.cfg

If a “grub.cfg” is found in any subdirectories other than “/boot/grub2” and “/boot/efi/EFI/redhat”, ask the System Administrator (SA) if there is documentation signed by the ISSO to approve the use of removable media as a boot loader. 

Check that the grub configuration file has the set root command in each menu entry with the following commands:

# grep -c menuentry /boot/grub2/grub.cfg
1
# grep ‘set root’ /boot/grub2/grub.cfg
set root=(hd0,1)

If the system is using an alternate boot loader on removable media, and documentation does not exist approving the alternate configuration, this is a finding.

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




RHEL-07-030090 - The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.\n\nAudit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.\n\nThis requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.\n\nSatisfies: SRG-OS-000046-GPOS-00022, SRG-OS-000047-GPOS-00023

Check
~~~~~

Confirm the audit configuration regarding how auditing processing failures are handled.

Check to see what level auditctl is set to in /etc/audit/auditd.conf with the following command: 

# grep \-f /etc/audit/auditd.conf
auditctl -f 2

If the value of "-f" is set to “2”, the system is configured to panic (shut down) in the event of an auditing failure.

If the value of "-f" is set to “1”, the system is configured to only send information to the kernel log regarding the failure.

If the "-f" flag is not set, this is a CAT I finding.

If the "-f" flag is set to any value other than “1” or “2”, this is a CAT II finding.

If the "-f" flag is set to “1” but the availability concern is not documented or there is no monitoring of the kernel log, this is a CAT III finding.

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

* Control Correlation Identifiers: CCI-000139


----




RHEL-07-030310 - All privileged function executions must be audited.
--------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

Check
~~~~~

Verify the operating system audits the execution of privileged functions.

To find relevant setuid and setgid programs, use the following command once for each local partition [PART]:

# find [PART] -xdev -local -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null

Run the following command to verify entries in the audit rules for all programs found with the previous command:

#grep <suid_prog_with_full_path>
a always,exit -F <suid_prog_with_full_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid

All setuid and setgid files on the system must have a corresponding audit rule, or must have an audit rule for the (sub) directory that contains the setuid/setgid file.

If all setuid/setgid files on the system do not have audit rule coverage, this is a finding.

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

* Control Correlation Identifiers: CCI-002234


----




RHEL-07-030330 - The operating system must off-load audit records onto a different system or media from the system being audited.
---------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Information stored in one location is vulnerable to accidental or incidental deletion or alteration.\n\nOff-loading is a common process in information systems with limited audit storage capacity.\n\nSatisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224

Check
~~~~~

Verify the operating system off-loads audit records onto a different system or media from the system being audited.

To determine the remote server that the records are being sent to, use the following command:

# grep -i remote_server /etc/audisp/audisp-remote.conf
remote_server = 10.0.21.1

If a remote server is not configured, or the line is commented out, this is a finding.

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

* Control Correlation Identifiers: CCI-001851


----




RHEL-07-030331 - The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.
-----------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Information stored in one location is vulnerable to accidental or incidental deletion or alteration.\n\nOff-loading is a common process in information systems with limited audit storage capacity.\n\nSatisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224

Check
~~~~~

Verify the operating system encrypts audit records off-loaded onto a different system or media from the system being audited.

To determine if the transfer is encrypted, use the following command:

# grep -i enable_krb5 /etc/audisp/audisp-remote.conf
enable_krb5 = yes

If the value of the “enable_krb5” option is not set to "yes" or the line is commented out, this is a finding.

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

* Control Correlation Identifiers: CCI-001851


----




RHEL-07-030340 - The audit system must take appropriate action when the audit storage volume is full.
-----------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.

Check
~~~~~

Verify the action the operating system takes if the disk the audit records are written to becomes full.

To determine the action that takes place if the disk is full on the remote server, use the following command:

# grep -i disk_full_action /etc/audisp/audisp-remote.conf
disk_full_action = single

To determine the action that takes place if the network connection fails, use the following command:

# grep -i network_failure_action /etc/audisp/audisp-remote.conf
network_failure_action = stop

If the value of the “network_failure_action” option is not “syslog”, “single”, or “halt”, or the line is commented out, this is a finding.

If the value of the “disk_full_action” option is not "syslog", "single", or "halt", or the line is commented out, this is a finding.

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

* Control Correlation Identifiers: CCI-001851


----




RHEL-07-030350 - The operating system must immediately notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.

Check
~~~~~

Verify the operating system immediately notifies the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.

Check the system configuration to determine the partition the audit records are being written to with the following command:

# grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to (with the example being /var/log/audit/):

# df -h /var/log/audit/
0.9G /var/log/audit

If the audit records are not being written to a partition specifically created for audit records (in this example /var/log/audit is a separate partition), determine the amount of space other files in the partition are currently occupying with the following command:

# du -sh <partition>
1.8G /var

Determine what the threshold is for the system to take action when 75 percent of the repository maximum audit record storage capacity is reached:

# grep -i space_left /etc/audit/auditd.conf
space_left = 225 

If the value of the “space_left” keyword is not set to 75 percent of the total partition size, this is a finding.

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

* Control Correlation Identifiers: CCI-001855


----




RHEL-07-030351 - The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost.

Check
~~~~~

Verify the operating system immediately notifies the SA and ISSO (at a minimum) via email when the allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.

Check what action the operating system takes when the threshold for the repository maximum audit record storage capacity is reached with the following command:

# grep -I space_left_action  /etc/audit/auditd.conf
space_left_action = email

If the value of the “space_left_action” keyword is not set to email, this is a finding.

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

* Control Correlation Identifiers: CCI-001855


----




RHEL-07-030352 - The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost.

Check
~~~~~

Verify the operating system immediately notifies the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached.

Check what account the operating system emails when the threshold for the repository maximum audit record storage capacity is reached with the following command:

# grep -i action_mail_acct  /etc/audit/auditd.conf
action_mail_acct = root

If the value of the “action_mail_acct” keyword is not set to “root” and other accounts for security personnel, this is a finding.

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

* Control Correlation Identifiers: CCI-001855


----




RHEL-07-030380 - All uses of the chown command must be audited.
---------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000392-GPOS-00172, SRG-OS-000458-GPOS-00203, SRG-OS-000474-GPOS-00219

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “chown” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i chown /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-000126


----




RHEL-07-030381 - All uses of the fchown command must be audited.
----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000392-GPOS-00172, SRG-OS-000458-GPOS-00203, SRG-OS-000474-GPOS-00219

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “fchown” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i fchown /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-000126


----




RHEL-07-030382 - All uses of the lchown command must be audited.
----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000392-GPOS-00172, SRG-OS-000458-GPOS-00203, SRG-OS-000474-GPOS-00219

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “lchown” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i lchown /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-000126


----




RHEL-07-030383 - All uses of the fchownat command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000392-GPOS-00172, SRG-OS-000458-GPOS-00203, SRG-OS-000474-GPOS-00219

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “fchownat” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i fchownat /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-000126


----




RHEL-07-030390 - All uses of the chmod command must be audited.
---------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000458-GPOS-00203, SRG-OS-000392-GPOS-00172, SRG-OS-000064-GPOS-00033

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “chmod” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following command:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i chmod /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030391 - All uses of the fchmod command must be audited.
----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000458-GPOS-00203, SRG-OS-000392-GPOS-00172, SRG-OS-000064-GPOS-00033

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “fchmod” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following command:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i fchmod /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030392 - All uses of the fchmodat command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000458-GPOS-00203, SRG-OS-000392-GPOS-00172, SRG-OS-000064-GPOS-00033

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “fchmodat” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following command:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i fchmodat /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030400 - All uses of the setxattr command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000458-GPOS-00203, SRG-OS-000392-GPOS-00172, SRG-OS-000064-GPOS-00033

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “setxattr” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i setxattr /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030401 - All uses of the fsetxattr command must be audited.
-------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000458-GPOS-00203, SRG-OS-000392-GPOS-00172, SRG-OS-000064-GPOS-00033

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “fsetxattr” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i fsetxattr /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030402 - All uses of the lsetxattr command must be audited.
-------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000458-GPOS-00203, SRG-OS-000392-GPOS-00172, SRG-OS-000064-GPOS-00033

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “lsetxattr” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i lsetxattr /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030403 - All uses of the removexattr command must be audited.
---------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000458-GPOS-00203, SRG-OS-000392-GPOS-00172, SRG-OS-000064-GPOS-00033

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “removexattr” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i removexattr /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030404 - All uses of the fremovexattr command must be audited.
----------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000458-GPOS-00203, SRG-OS-000392-GPOS-00172, SRG-OS-000064-GPOS-00033

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “fremovexattr” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i fremovexattr /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030405 - All uses of the lremovexattr command must be audited.
----------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000458-GPOS-00203, SRG-OS-000392-GPOS-00172, SRG-OS-000064-GPOS-00033

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “lremovexattr” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i lremovexattr /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030420 - All uses of the creat command must be audited.
---------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000458-GPOS-00203, SRG-OS-000461-GPOS-00205, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “creat” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i creat /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S creat  -Fexit=-EPERM -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

-a always,exit -F arch=b64 -S creat  -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030421 - All uses of the open command must be audited.
--------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000458-GPOS-00203, SRG-OS-000461-GPOS-00205, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “open” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i open /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S open -Fexit=-EPERM -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

-a always,exit -F arch=b64 -S  open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030422 - All uses of the openat command must be audited.
----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000458-GPOS-00203, SRG-OS-000461-GPOS-00205, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “openat” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i openat /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S openat -Fexit=-EPERM -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

-a always,exit -F arch=b64 -S  openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030423 - All uses of the open_by_handle_at command must be audited.
---------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000458-GPOS-00203, SRG-OS-000461-GPOS-00205, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “open_by_handle_at” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i open_by_handle_at /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S open_by_handle_at -Fexit=-EPERM -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

-a always,exit -F arch=b64 -S  open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030424 - All uses of the truncate command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000458-GPOS-00203, SRG-OS-000461-GPOS-00205, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “truncate” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i truncate /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S truncate -Fexit=-EPERM -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

-a always,exit -F arch=b64 -S  truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030425 - All uses of the ftruncate command must be audited.
-------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000458-GPOS-00203, SRG-OS-000461-GPOS-00205, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “ftruncate” command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i ftruncate /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b32 -S ftruncate -Fexit=-EPERM -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

-a always,exit -F arch=b64 -S  ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=access

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030441 - All uses of the semanage command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000463-GPOS-00207, SRG-OS-000465-GPOS-00209

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “semanage” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /usr/sbin/semanage /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding.

-a always,exit -F path=/usr/sbin/semanage
-F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-priv_change

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030442 - All uses of the setsebool command must be audited.
-------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000463-GPOS-00207, SRG-OS-000465-GPOS-00209

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “setsebool” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /usr/sbin/setsebool /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/sbin/setsebool
-F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-priv_change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030443 - All uses of the chcon command must be audited.
---------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000463-GPOS-00207, SRG-OS-000465-GPOS-00209

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “chcon” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /usr/bin/chcon /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/bin/chcon
-F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-priv_change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030444 - All uses of the restorecon command must be audited.
--------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000463-GPOS-00207, SRG-OS-000465-GPOS-00209

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “restorecon” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /usr/sbin/restorecon /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/sbin/restorecon
-F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-priv_change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030490 - The operating system must generate audit records for all successful/unsuccessful account access count events.
------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful account access count events occur. 

Check the file system rule in /etc/audit/rules.d/audit.rules with the following commands: 

# grep -i /var/log/tallylog etc/audit/audit.rules

-w /var/log/tallylog -p wa -k logins

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884, CCI-000126


----




RHEL-07-030491 - The operating system must generate audit records for all unsuccessful account access events.
-------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218

Check
~~~~~

Verify the operating system generates audit records when unsuccessful account access events occur. 

Check the file system rule in /etc/audit/rules.d/audit.rules with the following commands: 

# grep -i /var/run/faillock etc/audit/audit.rules

-w /var/run/faillock -p wa -k logins

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884, CCI-000126


----




RHEL-07-030492 - The operating system must generate audit records for all successful account access events.
-----------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218

Check
~~~~~

Verify the operating system generates audit records when successful account access events occur. 

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands: 

# grep -i /var/log/lastlog etc/audit/audit.rules

-w /var/log/lastlog -p wa -k logins 

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884, CCI-000126


----




RHEL-07-030510 - All uses of the passwd command must be audited.
----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “passwd” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /usr/bin/passwd /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-passwd

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030511 - All uses of the unix_chkpwd command must be audited.
---------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “unix_chkpwd” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /sbin/unix_chkpwd /etc/audit/rules.d/audit.rules

-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-passwd

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030512 - All uses of the gpasswd command must be audited.
-----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “gpasswd” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /usr/bin/gpasswd /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-passwd

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030513 - All uses of the chage command must be audited.
---------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “chage” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /usr/bin/chage /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-passwd

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030514 - All uses of the userhelper command must be audited.
--------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “userhelper” command occur.

Check the file system rule in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /usr/sbin/userhelper /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-passwd

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030521 - All uses of the su command must be audited.
------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “su” command occur.

Check for the following system call being audited by performing the following command to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /bin/su /etc/audit/rules.d/audit.rules

-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-priv_change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000130, CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030522 - All uses of the sudo command must be audited.
--------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “sudo” command occur.

Check for the following system calls being audited by performing the following command to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /usr/bin/sudo /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000130, CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030526 - All uses of the sudoedit command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “sudoedit” command occur.

Check for the following system calls being audited by performing the following command to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /usr/bin/sudoedit /etc/audit/rules.d/audit.rules

-a always,exit -F path=/bin/sudoedit-F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000130, CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030523 - The operating system must generate audit records containing the full-text recording of modifications to sudo configuration files.
--------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records containing the full-text recording of modifications to sudo configuration files. 

Check for modification of the following files being audited by performing the following commands to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /etc/sudoers /etc/audit/rules.d/audit.rules

-w /etc/sudoers -p wa -k privileged-actions

# grep -i /etc/sudoers.d/etc/audit/rules.d/audit.rules

-w /etc/sudoers.d/ -p wa -k privileged-actions

If the command does not return output that does not match the examples, this is a finding.

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

* Control Correlation Identifiers: CCI-000130, CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030524 - All uses of the newgrp command must be audited.
----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “newgrp” command occur.

Check for the following system call being audited by performing the following command to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /usr/bin/newgrp /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-priv_change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000130, CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030525 - All uses of the chsh command must be audited.
--------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “chsh” command occur.

Check for the following system call being audited by performing the following command to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /usr/bin/chsh /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-priv_change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000130, CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030530 - All uses of the mount command must be audited.
---------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged mount commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “mount” command occur.

Check for the following system calls being audited by performing the following series of commands to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /bin/mount /etc/audit/rules.d/audit.rules

-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-mount

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-002884


----




RHEL-07-030531 - All uses of the umount command must be audited.
----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged mount commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the “umount” command occur.

Check for the following system calls being audited by performing the following series of commands to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /bin/umount /etc/audit/rules.d/audit.rules

-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount  

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-002884


----




RHEL-07-030540 - All uses of the postdrop command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged postfix commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the postdrop command occur.

Check for the following system call being audited by performing the following command to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /usr/sbin/postdrop /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-postfix

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-002884


----




RHEL-07-030541 - All uses of the postqueue command must be audited.
-------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged postfix commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the postdrop command occur.

Check for the following system call being audited by performing the following command to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /usr/sbin/postqueue /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-postfix

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-002884


----




RHEL-07-030550 - All uses of the ssh-keysign command must be audited.
---------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged ssh commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the ssh-keysign command occur. 

Check for the following system call being audited by performing the following command to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /usr/libexec/openssh/ssh-keysign /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-ssh

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030560 - All uses of the pt_chown command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the pt_chown command occur. 

Check for the following system call being audited by performing the following command to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /usr/libexec/pt_chown /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged_terminal

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030561 - All uses of the crontab command must be audited.
-----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.\n\nAt a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.\n\nSatisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the crontab command occur. 

Check for the following system call being audited by performing the following command to check the file system rules in /etc/audit/rules.d/audit.rules: 

# grep -i /usr/bin/crontab /etc/audit/rules.d/audit.rules

-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-cron

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000135, CCI-000172, CCI-002884


----




RHEL-07-030630 - All uses of the pam_timestamp_check command must be audited.
-----------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the pam_timestamp_check command occur. 

Check the auditing rules in /etc/audit/rules.d/audit.rules with the following command:

# grep -i /sbin/pam_timestamp_check /etc/audit/rules.d/audit.rules

-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295  -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k privileged-pam  

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030670 - All uses of the init_module command must be audited.
---------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the init_module command occur. 

Check the auditing rules in /etc/audit/rules.d/audit.rules with the following command:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the line appropriate for the system architecture must be present.

# grep -i init_module /etc/audit/etc/audit/rules.d/audit.rules

If the command does not return the following output (appropriate to the architecture), this is a finding. 

-a always,exit -F arch=b32 -S init_module -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

-a always,exit -F arch=b64 -S init_module  -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030671 - All uses of the delete_module command must be audited.
-----------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the delete_module command occur. 

Check the auditing rules in /etc/audit/rules.d/audit.rules with the following command:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the line appropriate for the system architecture must be present.

# grep -i delete_module /etc/audit/etc/audit/rules.d/audit.rules

If the command does not return the following output (appropriate to the architecture), this is a finding. 

-a always,exit -F arch=b32  -S delete_module -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

-a always,exit -F arch=b64  -S delete_module -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030672 - All uses of the insmod command must be audited.
----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the insmod command occur. 

Check the auditing rules in /etc/audit/rules.d/audit.rules with the following command:

# grep -i insmod /etc/audit/etc/audit/rules.d/audit.rules

If the command does not return the following output (appropriate to the architecture), this is a finding. 

-w /sbin/insmod -p x -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030673 - All uses of the rmmod command must be audited.
---------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the rmmod command occur. 

Check the auditing rules in /etc/audit/rules.d/audit.rules with the following command:

# grep -i rmmod /etc/audit/etc/audit/rules.d/audit.rules

If the command does not return the following output (appropriate to the architecture), this is a finding. 

-w /sbin/rmmod -p x -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030674 - All uses of the modprobe command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. \n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the modprobe command occur. 

Check the auditing rules in /etc/audit/rules.d/audit.rules with the following command:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the line appropriate for the system architecture must be present.

# grep -i modprobe /etc/audit/etc/audit/rules.d/audit.rules

If the command does not return the following output (appropriate to the architecture), this is a finding. 

-w /sbin/modprobe -p x -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=module-change

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172


----




RHEL-07-030710 - The operating system must generate audit records for all account creations, modifications, disabling, and termination events.
----------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.\n\nAudit records can be generated from various components within the information system (e.g., module or policy filter).\n\nSatisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000241-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221

Check
~~~~~

Verify the operating system automatically audits account creation by performing the following series of commands to check the file system rules in /etc/audit/rules.d/audit.rules:

# grep /etc/group /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding. 

-w /etc/group -p wa -k audit_rules_usergroup_modification

# grep /etc/passwd /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding. 

-w /etc/passwd -p wa -k audit_rules_usergroup_modification

# grep /etc/gshadow /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding. 

-w /etc/gshadow -p wa -k audit_rules_usergroup_modification

# grep /etc/shadow /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding. 

-w /etc/shadow -p wa -k audit_rules_usergroup_modification

# grep /etc/security/opasswd /etc/audit/rules.d/audit.rules

If the command does not return the following output, this is a finding. 

-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification

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

* Control Correlation Identifiers: CCI-000018, CCI-000172, CCI-001403, CCI-002130


----




RHEL-07-030750 - All uses of the rename command must be audited.
----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.\n\nSatisfies: SRG-OS-000466-GPOS-00210, SRG-OS-000467-GPOS-00210, SRG-OS-000468-GPOS-00212, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the rename command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i rename /etc/audit/rules.d/audit.rules
-a always,exit -F arch=b32 -S rename -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete
-a always,exit -F arch=b64 -S rename -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030751 - All uses of the renameat command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.\n\nSatisfies: SRG-OS-000466-GPOS-00210, SRG-OS-000467-GPOS-00210, SRG-OS-000468-GPOS-00212, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the renameat command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i renameat  /etc/audit/rules.d/audit.rules
-a always,exit -F arch=b32 -S renameat  -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete
-a always,exit -F arch=b64 -S renameat  -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030752 - All uses of the rmdir command must be audited.
---------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.\n\nSatisfies: SRG-OS-000466-GPOS-00210, SRG-OS-000467-GPOS-00210, SRG-OS-000468-GPOS-00212, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the rmdir command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i rmdir /etc/audit/rules.d/audit.rules
-a always,exit -F arch=b32 -S rmdir  -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete
-a always,exit -F arch=b64 -S rmdir  -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030753 - All uses of the unlink command must be audited.
----------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.\n\nSatisfies: SRG-OS-000466-GPOS-00210, SRG-OS-000467-GPOS-00210, SRG-OS-000468-GPOS-00212, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the unlink command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i unlink/etc/audit/rules.d/audit.rules
-a always,exit -F arch=b32 -S unlink -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete
-a always,exit -F arch=b64 -S unlink  -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030754 - All uses of the unlinkat command must be audited.
------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.\n\nSatisfies: SRG-OS-000466-GPOS-00210, SRG-OS-000467-GPOS-00210, SRG-OS-000468-GPOS-00212, SRG-OS-000392-GPOS-00172

Check
~~~~~

Verify the operating system generates audit records when successful/unsuccessful attempts to use the unlinkat command occur.

Check the file system rules in /etc/audit/rules.d/audit.rules with the following commands:

Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.

# grep -i unlinkat/etc/audit/rules.d/audit.rules
-a always,exit -F arch=b32 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete
-a always,exit -F arch=b64 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -F subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -k delete

If the command does not return any output, this is a finding.

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

* Control Correlation Identifiers: CCI-000172, CCI-002884


----




RHEL-07-030770 - The system must send rsyslog output to a log aggregation server.
---------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Sending rsyslog output to another system ensures that the logs cannot be removed or modified in the event that the system is compromised or has a hardware failure.

Check
~~~~~

Verify “rsyslog” is configured to send all messages to a log aggregation server.

Check the configuration of “rsyslog” with the following command:

# grep @ /etc/rsyslog.conf
*.* @@logagg.site.mil

If there are no lines in the “/etc/rsyslog.conf” file that contain the “@” or “@@” symbol(s), and the lines with the correct symbol(s) to send output to another system do not cover all “rsyslog” output, this is a finding.

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




RHEL-07-030780 - The rsyslog daemon must not accept log messages from other servers unless the server is being used for log aggregation.
----------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial of Service.\nIf the system is intended to be a log aggregation server its use must be documented with the ISSO.

Check
~~~~~

Verify that the system is not accepting "rsyslog" messages from other systems unless it is documented as a log aggregation server.

Check the configuration of rsyslog with the following command:

# grep imtcp /etc/rsyslog.conf
ModLoad imtcp

If the "imtcp" module is being loaded in the "/etc/rsyslog.conf" file ask to see the documentation for the system being used for log aggregation.

If the documentation does not exist, or does not specify the server as a log aggregation system, this is a finding.

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




RHEL-07-030820 - The system must update the DoD-approved virus scan program every seven days or more frequently.
----------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.  \n\nThe virus scanning software should be configured to check for software and virus definition updates with a frequency no longer than seven days. If a manual process is required to update the virus scan software or definitions, it must be documented with the Information System Security Manager (ISSM).

Check
~~~~~

Verify the system is using a DoD-approved virus scan program and the virus definition file is less than seven days old.

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

If “McAfee VirusScan Enterprise for Linux” is active on the system, check the dates of the virus definition files with the following command:

# ls -al /opt/NAI/LinuxShield/engine/dat/*.dat
<need output>

If the virus definition files have dates older than seven days from the current date, this is a finding.

If “clamav” is active on the system, check the dates of the virus database with the following commands:

# grep -I databasedirectory /etc/clamav.conf
DatabaseDirectory /var/lib/clamav

# ls -al /var/lib/clamav/*.cvd
-rwxr-xr-x  1 root root      149156 Mar  5  2011 daily.cvd

If the database file has a date older than seven days from the current date, this is a finding.

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




RHEL-07-040020 - The system must log informational authentication data.
-----------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Access services, such as those providing remote access to network devices and information systems, that lack automated monitoring capabilities increase risk and make remote user access management difficult at best.\n\nAutomated monitoring of access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

Check
~~~~~

Verify the operating system logs informational authentication data.

Check to see if rsyslog is logging authentication information with the following commands:

# grep auth* /etc/rsyslog.conf
auth,authpriv.debug /var/log/auth.log

# grep daemon.* /etc/rsyslog.conf
daemon.notice /var/log/messages

If the auth, authpriv, and daemon facilities are not being logged, or they are being logged at a priority of notice or higher, this is a finding.

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

* Control Correlation Identifiers: CCI-000067, CCI-000126


----




RHEL-07-040030 - The operating system, for PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.
---------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

A certificate\xe2\x80\x99s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.  \n\nWhen there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.\n\nCertification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses. \n\nOperating systems that do not validate certificates by performing RFC 5280-compliant certification path validation to a trust anchor are in danger of accepting certificates that are invalid and or counterfeit. This could allow unauthorized access to a system.

Check
~~~~~

Verify the operating system, for PKI–based authentication, validates certificates by performing RFC 5280–compliant certification path validation.

Check to see if Online Certificate Status Protocol (OCSP) is enabled on the system with the following command:

# grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf
cert_policy =ca, ocsp_on, signature;
cert_policy =ca, ocsp_on, signature;
cert_policy =ca, ocsp_on, signature;

There must be at least three lines returned. If oscp_on is present in all cert_policy lines this is not a finding.

If oscp_on is not present in all lines check for the presence of certificate revocation lists:

# grep crl_dir = /etc/pam_pkcs11/crls
crl_dir = /etc/pam_pkcs11/crls;

Check the returned directory for the presence of a crl file.

If the file exists this in the configured directory is not a finding.

If the system is not configured to use OCSP or crls, or the crls file is missing, this is a finding.

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

* Control Correlation Identifiers: CCI-000185


----




RHEL-07-040040 - The operating system, for PKI-based authentication, must enforce authorized access to all PKI private keys stored or used by the operating system.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.\n\nThe cornerstone of the PKI is the private key used to encrypt or digitally sign information.\n\nIf private keys are stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key(s) to digitally sign data and thus impersonate the associated subjects (systems or users).\n\nBoth the holders of a digital certificate and the issuing authority must take careful measures to protect the corresponding private keys. Private keys should always be generated and protected in appropriate FIPS 140-2 validated cryptographic modules.

Check
~~~~~

Verify the operating system, for PKI–based authentication, enforces authorized access to all PKI private keys stored/utilized by the operating system.

Check the module being used by the system smartcard architecture with the following command:

# grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf
use_pkcs11_module = cackey; 

If the module returned is not cackey or coolkey, or the line is commented out, this is a finding.

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

* Control Correlation Identifiers: CCI-000186


----




RHEL-07-040050 - The operating system must map the authenticated identity to the user or group account for PKI-based authentication.
------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

Check
~~~~~

Verify the operating system maps the authenticated identity to the user or group account for PKI–based authentication by verifying the common name map file exists with the following command:

# ls –al /etc/pam_pkcs11/cn_map
–rw–r––––– 1 root root 1294 Apr 22 17:22 /etc/pam_pkcs11/subject_mapping

If the file does not exist, this is a finding.

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

* Control Correlation Identifiers: CCI-000187


----




RHEL-07-040060 - The cn_map file must have mode 0644 or less permissive.
------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

Check
~~~~~

Verify the operating system protects the file that maps the authenticated identity to the user or group account for PKI–based authentication.

Check the mode on the cn_map file with the following command:

# ls –al /etc/pam_pkcs11/cn_map
–rw––––––– 1 root root 1294 Apr 22 17:22 /etc/pam_pkcs11/cn_map

If the cn_map file has a mode more permissive than “0644”, this is a finding.

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

* Control Correlation Identifiers: CCI-000187


----




RHEL-07-040070 - The cn_map file must be owned by root.
-------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

Check
~~~~~

Verify the operating system protects the file that maps the authenticated identity to the user or group account for PKI–based authentication.

Check the owner on the cn_map file with the following command:

# ls –al /etc/pam_pkcs11/cn_map
–rw––––––– 1 root root 1294 Apr 22 17:22 /etc/pam_pkcs11/cn_map

If the cn_map file has an owner other than root, this is a finding.

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

* Control Correlation Identifiers: CCI-000187


----




RHEL-07-040080 - The cn_map file must be group owned by root.
-------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

Check
~~~~~

Verify the operating system protects the file that maps the authenticated identity to the user or group account for PKI–based authentication.

Check the group owner on the cn_map file with the following command:

# ls –al /etc/pam_pkcs11/cn_map
–rw––––––– 1 root root 1294 Apr 22 17:22 /etc/pam_pkcs11/cn_map

If the cn_map file has a group owner other than root, this is a finding.

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

* Control Correlation Identifiers: CCI-000187


----




RHEL-07-040100 - The host must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.\n\nOperating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.\n\nTo support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.\n\nSatisfies: SRG-OS-000096-GPOS-00050, SRG-OS-000297-GPOS-00115

Check
~~~~~

Inspect the firewall configuration and running services to verify that it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited.

Check which services are currently active with the following command:

# firewall-cmd --list-all
public (default, active)
  interfaces: enp0s3
  sources: 
  services: dhcpv6-client dns http https ldaps rpc-bind ssh
  ports: 
  masquerade: no
  forward-ports: 
  icmp-blocks: 
  rich rules: 

Ask the system administrator for the site or program PPSM CLSA. Verify the services allowed by the firewall match the PPSM CLSA. 

If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding.

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

* Control Correlation Identifiers: CCI-000382, CCI-002314


----




RHEL-07-040110 - A FIPS 140-2 approved cryptographic algorithm must be used for SSH communications.
---------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.\n\nOperating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.\n\nFIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.\n\nSatisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000120-GPOS-00061, SRG-OS-000125-GPOS-00065, SRG-OS-000250-GPOS-00093, SRG-OS-000393-GPOS-00173

Check
~~~~~

Verify the operating system uses mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

Note: If RHEL-07-021280 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.

The location of the sshd_config file may vary on the system and can be found using the following command:

# find / -name ‘sshd*_config’

If there is more than one ssh server daemon configuration file on the system, determine which daemons are active on the system with the following command:

# ps -ef | grep sshd

The command will return the full path of the ssh daemon. This will indicate which sshd_config file will be checked with the following command:

# grep -i ciphers /etc/ssh/sshd_config
Ciphers aes128-ctr aes192-ctr, aes256-ctr

If any ciphers other than “aes128-ctr”, “aes192-ctr”, or “aes256-ctr” are listed, the “Ciphers” keyword is missing, or the retuned line is commented out, this is a finding.

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

* Control Correlation Identifiers: CCI-000068, CCI-000366, CCI-000803


----




RHEL-07-040160 - All network connections associated with a communication session must be terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. \n\nTerminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

Check
~~~~~

Verify the operating system terminates all network connections associated with a communications session at the end of the session or based on inactivity.

Check the value of the system inactivity timeout with the following command:

# grep -i tmout /etc/profile 
TMOUT=600

If “TMOUT” is not set to 600 or less in /etc/profile, this is a finding.

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

* Control Correlation Identifiers: CCI-001133, CCI-002361


----




RHEL-07-040170 - The Standard Mandatory DoD Notice and Consent Banner must be displayed immediately prior to, or as part of, remote access logon prompts.
---------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.\n\nSystem use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.\n\nThe banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:\n\n"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."\n\nSatisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007 , SRG-OS-000228-GPOS-00088

Check
~~~~~

Verify any publicly accessible connection to the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.

Check for the location of the banner file being used with the following command:

# grep -i banner /etc/ssh/sshd_config

banner=/etc/issue

This command will return the banner keyword and the name of the file that contains the ssh banner (in this case /etc/issue).

If the line is commented out, this is a finding.

View the file specified by the banner keyword to check that it matches the text of the Standard Mandatory DoD Notice and Consent Banner:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.”

If the system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

If the text in the file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

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

* Control Correlation Identifiers: CCI-000048, CCI-000050, CCI-001384, CCI-001385, CCI-001386, CCI-001387, CCI-001388


----




RHEL-07-040180 - The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without cryptographic integrity protections, information can be altered by unauthorized users without detection.\n\nCryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

Check
~~~~~

Verify the operating system implements cryptography to protect the integrity of remote LDAP authentication sessions.

To determine if LDAP is being used for authentication, use the following command:

# grep -i useldapauth /etc/sysconfig/authconfig
USELDAPAUTH=yes

If USELDAPAUTH=yes, then LDAP is being used. To see if LDAP is configured to use TLS, use the following command:

# grep -i ssl /etc/pam_ldap.conf
ssl start_tls

If the “ssl” option is not “start_tls”, this is a finding.

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

* Control Correlation Identifiers: CCI-001453


----




RHEL-07-040181 - The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.
----------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without cryptographic integrity protections, information can be altered by unauthorized users without detection.\n\nCryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

Check
~~~~~

Verify the operating system implements cryptography to protect the integrity of remote LDAP access sessions.

To determine if LDAP is being used for authentication, use the following command:

# grep -i useldapauth /etc/sysconfig/authconfig
USELDAPAUTH=yes

If USELDAPAUTH=yes, then LDAP is being used. 

Check for the directory containing X.509 certificates for peer authentication with the following command:

# grep -i cacertdir /etc/pam_ldap.conf
tls_cacertdir /etc/openldap/certs

Verify the directory set with the “tls_cacertdir” option exists.

If the directory does not exist or the option is commented out, this is a finding.

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

* Control Correlation Identifiers: CCI-001453


----




RHEL-07-040182 - The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.
----------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without cryptographic integrity protections, information can be altered by unauthorized users without detection.\n\nCryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

Check
~~~~~

Verify the operating system implements cryptography to protect the integrity of remote ldap access sessions.

To determine if LDAP is being used for authentication, use the following command:

# grep -i useldapauth /etc/sysconfig/authconfig
USELDAPAUTH=yes

If USELDAPAUTH=yes, then LDAP is being used.

Check that the path to the X.509 certificate for peer authentication with the following command:

# grep -i cacertfile /etc/pam_ldap.conf
tls_cacertfile /etc/openldap/ldap-cacert.pem

Verify the “tls_cacertfile” option points to a file that contains the trusted CA certificate.

If this file does not exist, or the option is commented out or missing, this is a finding.

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

* Control Correlation Identifiers: CCI-001453


----




RHEL-07-040190 - All network connections associated with SSH traffic must terminate at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.\n\nTerminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.\n\nSatisfies: SRG-OS-000163-GPOS-00072, SRG-OS-000279-GPOS-00109

Check
~~~~~

Verify the operating system automatically terminates a user session after inactivity time-outs have expired.

Check for the value of the ClientAlive keyword with the following command:

# grep -i clientalive /etc/ssh/sshd_config

ClientAliveInterval 600

If “ClientAliveInterval” is not set to “600” in /etc/ ssh/sshd_config, and a lower value is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

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

* Control Correlation Identifiers: CCI-001133, CCI-002361


----




RHEL-07-040191 - All network connections associated with SSH traffic must terminate after a period of inactivity.
-----------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.\n\nTerminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.\n\nSatisfies: SRG-OS-000163-GPOS-00072, SRG-OS-000279-GPOS-00109

Check
~~~~~

Verify the operating system automatically terminates a user session after inactivity time-outs have expired.

Check for the value of the ClientAliveCountMax keyword with the following command:

# grep -i clientalivecount /etc/ssh/sshd_config
ClientAliveCountMax 0

If “ClientAliveCountMax” is not set to “0” in /etc/ ssh/sshd_config, this is a finding.

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

* Control Correlation Identifiers: CCI-001133, CCI-002361


----




RHEL-07-040210 - The operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.\n\nSynchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.\n\nOrganizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).\n\nSatisfies: SRG-OS-000355-GPOS-00143, SRG-OS-000355-GPOS-00144

Check
~~~~~

Check to see if ntp is running in continuous mode.

# ps -ef | grep ntp

If NTP is not running, this is a finding.

If the process is found, then check the ntp.conf file for the “maxpoll” option setting:

# grep maxpoll /etc/ntp.conf
maxpoll 10

If the file does not exist, this is a finding.

If the option is set to “17” or is not set, this is a finding.

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

* Control Correlation Identifiers: CCI-001891, CCI-002046


----




RHEL-07-040230 - The operating system, if using PKI-based authentication, must implement a local cache of revocation data to certificate validation in case of the inability to access revocation information via the network.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).

Check
~~~~~

Verify the operating system, for PKI-based authentication, implements a local cache of revocation data to support certificate validation in case of the inability to access revocation information via the network.

Check to see if the certificate authority certificate revocation data cache is enabled on the system with the following command:

# grep -i  revocationchecking /var/lib/pki-ca/conf/CS.cfg
auths.revocationChecking.bufferSize=50
auths.revocationChecking.ca=ca
auths.revocationChecking.enabled=true
auths.revocationChecking.unknownStateInterval=0
auths.revocationChecking.validityInterval=120

If auths.revocationChecking.enabled is not set to "true", this is a finding.

If auths.revocationChecking.bufferSize is not set to a value of “50” or less, this is a finding.

Check to see if the Online Certificate Status Protocol (OCSP) certificate revocation data cache is enabled on the system with the following command: 

# grep -i ocsp /var/lib/pki-kra/conf/server.xml
enableOCSP="true"
ocspResponderURL="http://server.pki.mil:9180/ca/ocsp"
      ocspResponderCertNickname="ocspSigningCert cert-pki-ca 102409a"
        ocspCacheSize="50"
        ocspMinCacheEntryDuration="60"
        ocspMaxCacheEntryDuration="120"
        ocspTimeout="10"

If “enableOCSP” is not set to "true", this is a finding.

If “ocspCacheSize” is not set to a value of “50” or less, this is a finding.

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

* Control Correlation Identifiers: CCI-001991


----




RHEL-07-040250 - The operating system must protect against or limit the effects of Denial of Service (DoS) attacks by validating the operating system is implementing rate-limiting measures on impacted network interfaces.
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.\n\nThis requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

Check
~~~~~

Verify the operating system protects against or limits the effects of DoS attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.

Check the firewall configuration with the following command:

# firewall-cmd --direct --get-rule ipv4 filter IN_public_allow
rule ipv4 filter IN_public_allow 0 -m tcp -p tcp -m limit --limit 25/minute --limit-burst 100  -j ACCEPT

If a rule with both the limit and limit-burst arguments parameters does not exist, this is a finding.

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

* Control Correlation Identifiers: CCI-002385


----




RHEL-07-040260 - All networked systems must have SSH installed.
---------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. \n\nThis requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. \n\nProtecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.\n\nSatisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000423-GPOS-00188, SRG-OS-000423-GPOS-00189, SRG-OS-000423-GPOS-00190

Check
~~~~~

Check to see if sshd is installed with the following command:

# yum list installed | grep ssh
libssh2.x86_64                           1.4.3-8.el7               @anaconda/7.1
openssh.x86_64                           6.6.1p1-11.el7            @anaconda/7.1
openssh-clients.x86_64                   6.6.1p1-11.el7            @anaconda/7.1
openssh-server.x86_64                    6.6.1p1-11.el7            @anaconda/7.1

If the “SSH server” package is not installed, this is a finding.

If the “SSH client” package is not installed, this is a finding.

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

* Control Correlation Identifiers: CCI-002418, CCI-002421, CCI-002420, CCI-002422


----




RHEL-07-040261 - All networked systems must use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. \n\nThis requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. \n\nProtecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.\n\nSatisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000423-GPOS-00188, SRG-OS-000423-GPOS-00189, SRG-OS-000423-GPOS-00190

Check
~~~~~

Verify SSH is loaded and active with the following command:

# systemctl status sshd
 sshd.service - OpenSSH server daemon
   Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled)
   Active: active (running) since Tue 2015-11-17 15:17:22 EST; 4 weeks 0 days ago
 Main PID: 1348 (sshd)
   CGroup: /system.slice/sshd.service
           ??1348 /usr/sbin/sshd -D

If “sshd” does not show a status of “active” and “running”, this is a finding.

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

* Control Correlation Identifiers: CCI-002418, CCI-002421, CCI-002420, CCI-002422


----




RHEL-07-040290 - The operating system must enable an application firewall, if available.
----------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.\n\nSatisfies: SRG-OS-000480-GPOS-00227, SRG-OS-000480-GPOS-00231, SRG-OS-000480-GPOS-00232

Check
~~~~~

Verify the operating system enabled an application firewall.

Check to see if "firewalld" is installed with the following command:

# yum list installed | grep firewalld
firewalld-0.3.9-11.el7.noarch.rpm

If the “firewalld” package is not installed, ask the system administrator if another firewall application (such as iptables) is installed. If an application firewall is not installed, this is a finding. 

Check to see if the firewall is loaded and active with the following command:

# systemctl status firewalld - must show that the firewall if loaded and active
firewalld.service - firewalld - dynamic firewall daemon

   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
   Active: active (running) since Tue 2014-06-17 11:14:49 CEST; 5 days ago

If “firewalld” does not show a status of “loaded and active”, this is a finding. 

Check the state of the firewall:

# firewall-cmd --state 
running

If “firewalld” does not show a state of “running”, this is a finding.

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




RHEL-07-040301 - The system must display the date and time of the last successful account logon upon an SSH logon.
------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.

Check
~~~~~

Verify SSH provides users with feedback on when account accesses last occurred.

Check that “PrintLastLog” keyword in the sshd daemon configuration file is used and set to “yes” with the following command:

# grep -i printlastlog /etc/ssh/sshd_config
PrintLastLog yes

If the “PrintLastLog” keyword is set to “no”, is missing, or is commented out, this is a finding.

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




RHEL-07-040310 - The system must not permit direct logons to the root account using remote access via SSH.
----------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system.

Check
~~~~~

Verify remote access using SSH prevents users from logging on directly as root.

Check that SSH prevents users from logging on directly as root with the following command:

# grep -i permitrootlogin /etc/ssh/sshd_config
PermitRootLogin no

If the “PermitRootLogin” keyword is set to “yes”, is missing, or is commented out, this is a finding.

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




RHEL-07-040334 - The SSH daemon must not allow authentication using rhosts authentication.
------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.

Check
~~~~~

Verify the SSH daemon does not allow authentication using known hosts authentication.

To determine how the SSH daemon's "IgnoreRhosts" option is set, run the following command:

# grep -i IgnoreRhosts /etc/ssh/sshd_config

IgnoreRhosts yes

If the value is returned as “no”, the returned line is commented out, or no output is returned, this is a finding.

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




RHEL-07-040332 - The SSH daemon must not allow authentication using known hosts authentication.
-----------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.

Check
~~~~~

Verify the SSH daemon does not allow authentication using known hosts authentication.

To determine how the SSH daemon's "IgnoreUserKnownHosts" option is set, run the following command:

# grep -i IgnoreUserKnownHosts /etc/ssh/sshd_config

IgnoreUserKnownHosts yes

If the value is returned as “no”, the returned line is commented out, or no output is returned, this is a finding.

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




RHEL-07-040333 - The SSH daemon must not allow authentication using RSA rhosts authentication.
----------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.

Check
~~~~~

Verify the SSH daemon does not allow authentication using RSA rhosts authentication.

To determine how the SSH daemon's "RhostsRSAAuthentication" option is set, run the following command:

# grep -i IgnoreUserKnownHosts /etc/ssh/sshd_config

RhostsRSAAuthentication yes

If the value is returned as “no”, the returned line is commented out, or no output is returned, this is a finding.

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




RHEL-07-040350 - The system must not forward Internet Protocol version 4 (IPv4) source-routed packets.
------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.

Check
~~~~~

Verify the system does not accept IPv4 source-routed packets.

Check the value of the accept source route variable with the following command:

# /sbin/sysctl -a | grep  net.ipv4.conf.all.accept_source_route
net.ipv4.conf.all.accept_source_route=0

If the returned line does not have a value of “0”, a line is not returned, or the returned line is commented out, this is a finding.

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




RHEL-07-040351 - The system must not forward Internet Protocol version 4 (IPv4) source-routed packets by default.
-----------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.

Check
~~~~~

Verify the system does not accept IPv4 source-routed packets by default.

Check the value of the accept source route variable with the following command:

# /sbin/sysctl -a | grep  net.ipv4.conf.default.accept_source_route
net.ipv4.conf.default.accept_source_route=0

If the returned line does not have a value of “0”, a line is not returned, or the returned line is commented out, this is a finding.

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




RHEL-07-040380 - The system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.
---------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.

Check
~~~~~

Verify the system does not respond to IPv4 ICMP echoes sent to a broadcast address.

Check the value of the icmp_echo_ignore_broadcasts variable with the following command:

# /sbin/sysctl -a | grep  net.ipv4.icmp_echo_ignore_broadcasts
net.ipv4.icmp_echo_ignore_broadcasts=1

If the returned line does not have a value of “1”, a line is not returned, or the retuned line is commented out, this is a finding.

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




RHEL-07-040410 - The system must ignore to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.
-----------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

Check
~~~~~

Verify the system ignores IPv4 ICMP redirect messages.

Check the value of the “accept_redirects” variables with the following command:

# /sbin/sysctl -a | grep  'net.ipv4.conf.*.accept_redirects'
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_redirects=0

If both of the returned line do not have a value of “0”, a line is not returned, or the retuned line is commented out, this is a finding.

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




RHEL-07-040420 - The system must not allow interfaces to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects by default.
------------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.

Check
~~~~~

Verify the system does not allow interfaces to perform IPv4 ICMP redirects by default.

Check the value of the "default send_redirects" variables with the following command:

# /sbin/sysctl -a | grep  'net.ipv4.conf.default.send_redirects'
net.ipv4.conf.default.send_redirects=0

If the returned line does not have a value of “0”, a line is not returned, or the retuned line is commented out, this is a finding.

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




RHEL-07-040421 - The system must not send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects.
--------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.

Check
~~~~~

Verify the system does not send IPv4 ICMP redirect messages.

Check the value of the "all send_redirects" variables with the following command:

# /sbin/sysctl -a | grep  net.ipv4.conf.all.send_redirects

net.ipv4.conf.all.send_redirects=0

If the returned line does not have a value of “0”, a line is not returned, or the retuned line is commented out, this is a finding.

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




RHEL-07-040470 - Network interfaces must not be in promiscuous mode.
--------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Network interfaces in promiscuous mode allow for the capture of all network traffic visible to the system. If unauthorized individuals can access these applications, it may allow then to collect information such as logon IDs, passwords, and key exchanges between systems.\n\nIf the system is being used to perform a network troubleshooting function, the use of these tools must be documented with the Information System Security Manager (ISSM) and restricted to only authorized personnel.

Check
~~~~~

Verify network interfaces are not in promiscuous mode unless approved by the Information System Security Manager (ISSM) and documented.

Check for the status with the following command:

# ip link | grep -i promisc

If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSM and documented, this is a finding.

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




RHEL-07-040480 - The system must be configured to prevent unrestricted mail relaying.
-------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending spam or other unauthorized activity.

Check
~~~~~

Verify the system is configured to prevent unrestricted mail relaying.

Determine if "postfix" or "sendmail" are installed with the following commands:

# yum list installed | grep postfix
postfix-2.6.6-6.el7.x86_64.rpm 
# yum list installed | grep sendmail

If neither are installed, this is Not Applicable.

If postfix is installed, determine if it is configured to reject connections from unknown or untrusted networks with the following command:

# grep smtpd_client_restrictions /etc/postfix/main.cf
smtpd_client_restrictions = permit_mynetworks, reject

If the “smtpd_client_restrictions” parameter contains any entries other than "permit_mynetworks" and "reject", this is a finding.

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




RHEL-07-040520 - If the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon must be configured to operate in secure mode.
-----------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.

Check
~~~~~

Verify the TFTP daemon is configured to operate in secure mode.

Check to see if a TFTP server has been installed with the following commands:

# yum list installed | grep tftp
tftp-0.49-9.el7.x86_64.rpm

If a TFTP server is not installed, this is Not Applicable.

If a TFTP server is installed, check for the server arguments with the following command: 

# grep server_arge /etc/xinetd.d/tftp
server_args = -s /var/lib/tftpboot

If the “server_args” line does not have a -s option and the directory /var/lib/tftpboot, this is a finding.

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




RHEL-07-040560 - An X Windows display manager must not be installed unless approved.
------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. X Windows has a long history of security vulnerabilities and will not be used unless approved and documented.

Check
~~~~~

Verify that if the system has X Windows installed, it is authorized.

Check for the X11 package with the following command:

#yum groupinstall "X Window System"

Ask the System Administrator (SA) if use of the X Windows system is an operational requirement.

If the use of X Windows on the system is not documented with the Information System Security Manager (ISSM), this is a finding.

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




RHEL-07-040620 - The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.
---------------------------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions. The only SSHv2 hash algorithm meeting this requirement is SHA.

Check
~~~~~

Verify the SSH daemon is configured to only use MACs employing FIPS 140-2 approved ciphers.

Note: If RHEL-07-021280 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.

Check that the SSH daemon is configured to only use MACs employing FIPS 140-2 approved ciphers with the following command:

# grep -i macs /etc/ssh/sshd_config
MACs hmac-sha2-256,hmac-sha2-512

If any ciphers other than “hmac-sha2-256” or “hmac-sha2-512” are listed or the retuned line is commented out, this is a finding.

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

* Control Correlation Identifiers: CCI-001453


----




RHEL-07-040640 - The SSH public host key files must have mode 0644 or less permissive.
--------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If a public host key file is modified by an unauthorized user, the SSH service may be compromised.

Check
~~~~~

Verify the SSH public host key files have mode “0644” or less permissive.

Note: SSH public key files may be found in other directories on the system depending on the installation.

The following command will find all SSH public key files on the system:

# find / -name '*.pub'

Check the mode of the public host key files under /etc/ssh file with the following command:

# ls -lL /etc/ssh/*.pub
-rw-r--r--  1 root  wheel  618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r--  1 root  wheel  347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r--  1 root  wheel  238 Nov 28 06:43 ssh_host_rsa_key.pub

If any file has a mode more permissive than “0644”, this is a finding.

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




RHEL-07-040650 - The SSH private host key files must have mode 0600 or less permissive.
---------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If an unauthorized user obtains the private SSH host key file, the host could be impersonated.

Check
~~~~~

Verify the SSH private host key files have mode “0600” or less permissive.

The following command will find all SSH private key files on the system:

# find / -name '*ssh_host*key'

Check the mode of the private host key files under /etc/ssh file with the following command:

# ls -lL /etc/ssh/*key
-rw-------  1 root  wheel  668 Nov 28 06:43 ssh_host_dsa_key
-rw-------  1 root  wheel  582 Nov 28 06:43 ssh_host_key
-rw-------  1 root  wheel  887 Nov 28 06:43 ssh_host_rsa_key

If any file has a mode more permissive than “0600”, this is a finding.

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




RHEL-07-040660 - The SSH daemon must not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed.
---------------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system\xe2\x80\x99s GSSAPI to remote hosts, increasing the attack surface of the system. GSSAPI authentication must be disabled unless needed.

Check
~~~~~

Verify the SSH daemon does not permit GSSAPI authentication unless approved.

Check that the SSH daemon does not permit GSSAPI authentication with the following command:

# grep -i gssapiauth /etc/ssh/sshd_config
GSSAPIAuthentication no

If the “GSSAPIAuthentication” keyword is missing, is set to “yes” and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding.

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




RHEL-07-040670 - The SSH daemon must not permit Kerberos authentication unless needed.
--------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation. Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation. To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems not using this capability.

Check
~~~~~

Verify the SSH daemon does not permit Kerberos to authenticate passwords unless approved.

Check that the SSH daemon does not permit Kerberos to authenticate passwords with the following command:

# grep -i kerberosauth /etc/ssh/sshd_config
KerberosAuthentication no

If the “KerberosAuthentication” keyword is missing, or is set to "yes" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding.

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




RHEL-07-040680 - The SSH daemon must perform strict mode checking of home directory configuration files.
--------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.

Check
~~~~~

Verify the SSH daemon performs strict mode checking of home directory configuration files.

The location of the sshd_config file may vary on the system and can be found using the following command:

# find / -name 'sshd*_config' 

If there is more than one ssh server daemon configuration file on the system, determine which daemons are active on the system with the following command:

# ps -ef | grep sshd

The command will return the full path of the ssh daemon. This will indicate which sshd_config file will be checked with the following command:

# grep -i strictmodes /etc/ssh/sshd_config
StrictModes yes

If “StrictModes” is set to "no", is missing, or the retuned line is commented out, this is a finding.

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




RHEL-07-040690 - The SSH daemon must use privilege separation.
--------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.

Check
~~~~~

Verify the SSH daemon performs privilege separation.

Check that the SSH daemon performs privilege separation with the following command:

# grep -i usepriv /etc/ssh/sshd_config
UsePrivilegeSeparation yes

If the “UsePrivilegeSeparation” keyword is set to "no", is missing, or the retuned line is commented out, this is a finding.

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




RHEL-07-040700 - The SSH daemon must not allow compression or must only allow compression after successful authentication.
--------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.

Check
~~~~~

Verify the SSH daemon performs compression after a user successfully authenticates.

Check that the SSH daemon performs compression after a user successfully authenticates with the following command:

# grep -i compression /etc/ssh/sshd_config
Compression delayed

If the “Compression” keyword is set to “yes”, is missing, or the retuned line is commented out, this is a finding.

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




RHEL-07-040730 - The system must not be performing packet forwarding unless the system is a router.
---------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.

Check
~~~~~

Verify the system is not performing packet forwarding, unless the system is a router.

Check to see if IP forwarding is enabled using the following command:

# /sbin/sysctl -a | grep  net.ipv4.ip_forward
net.ipv4.ip_forward=0

If IP forwarding value is “1” and the system is hosting any application, database, or web servers, this is a finding.

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




RHEL-07-040740 - The Network File System (NFS) must be configured to use AUTH_GSS.
----------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

When an NFS server is configured to use AUTH_SYS, a selected userid and groupid are used to handle requests from the remote user. The userid and groupid could mistakenly or maliciously be set incorrectly. The AUTH_GSS method of authentication uses certificates on the server and client systems to more securely authenticate the remote mount request.

Check
~~~~~

Verify “AUTH_GSS’ is being used to authenticate NFS mounts.

To check if the system is importing an NFS file system, look for any entries in the “/etc/fstab” file that have a file system type of “nfs” with the following command:

# cat /etc/fstab | grep nfs
192.168.21.5:/mnt/export /data1 nfs4 rw,sync ,soft,sec=sys, krb5:krb5i:krb5p

If the system is mounting file systems via NFS and has the sec option without the “krb5:krb5i:krb5p” settings, the sec option has the “sys” setting, or the “sec” option is missing, this is a finding.

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




RHEL-07-040810 - The system must use a local firewall.
------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

A firewall provides the ability to enhance system security posture by restricting services to known good IP addresses and address ranges. This prevents connections from unknown hosts and protocols.

Check
~~~~~

Verify that a firewall is in use on the system.

Check to see if “firewalld” is installed with the following command:

# yum list installed | grep firewalld

If “firewalld” is not installed, ask the System Administrator if they are performing another method of access control (such as iptables) for all network services on the system. 

If there is no access control being performed on all network services, this is a finding.

If “firewalld” is installed, determine whether it is active with the following command:

# systemctl status firewalld
firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
   Active: active (running) since Sun 2014-04-20 14:06:46 BST; 30s ago

If “firewalld” is not active, this is a finding.

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




RHEL-07-040820 - The system's access control program must be configured to grant or deny system access to specific hosts and services.
--------------------------------------------------------------------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

If the systems access control program is not configured with appropriate rules for allowing and denying access to system network resources, services may be accessible to unauthorized hosts.

Check
~~~~~

If the “firewalld” package is not installed, ask the System Administrator if another firewall application (such as iptables) is installed. If an application firewall is not installed, this is a finding. 

Verify the system's access control program is configured to grant or deny system access to specific hosts.

Check to see if “firewalld” is active with the following command:

# systemctl status firewalld
firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
   Active: active (running) since Sun 2014-04-20 14:06:46 BST; 30s ago

If “firewalld” is active, check to see if it is configured to grant or deny access to specific hosts or services with the following commands:

# firewall-cmd --get-default-zone
public

# firewall-cmd --list-all --zone=public
public (default, active)
  interfaces: eth0
  sources:
  services: mdns ssh
  ports:
  masquerade: no
  forward-ports:
  icmp-blocks:
  rich rules:
 rule family="ipv4" source address="92.188.21.1/24" accept
 rule family="ipv4" source address="211.17.142.46/32" accept

If “firewalld” is not active, determine whether “tcpwrappers” is being used by checking whether the “hosts.allow” and “hosts.deny” files are empty with the following commands:

# ls -al /etc/hosts.allow
rw-r----- 1 root root 9 Aug  2 23:13 /etc/hosts.allow
 
# ls -al /etc/hosts.deny
-rw-r----- 1 root root  9 Apr  9  2007 /etc/hosts.deny

If “firewalld” and “tcpwrappers” are not installed, configured, and active, ask the System Administrator (SA) if another access control program (such as iptables) is installed and active. Ask the SA to show that the running configuration grants or denies access to specific hosts or services.

If “firewalld” is active and is not configured to grant access to specific hosts and “tcpwrappers” is not configured to grant or deny access to specific hosts, this is a finding.

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




RHEL-07-040830 - The system must not have unauthorized IP tunnels configured.
-----------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the Information System Security Officer (ISSO).

Check
~~~~~

Verify the system does not have unauthorized IP tunnels configured.

Check to see if “libreswan” is installed with the following command:

# yum list installed libreswan
openswan-2.6.32-27.el6.x86_64

If “libreswan” is installed, check to see if the “IPsec” service is active with the following command:

# systemctl status ipsec
ipsec.service - Internet Key Exchange (IKE) Protocol Daemon for IPsec
   Loaded: loaded (/usr/lib/systemd/system/ipsec.service; disabled)
   Active: inactive (dead)

If the “IPsec” service is active, check to see if any tunnels are configured in “/etc/ipsec.conf” and “/etc/ipsec.d/” with the following commands:

# grep -i conn /etc/ipsec.conf
conn mytunnel

# grep -i conn /etc/ipsec.d/*.conf
conn mytunnel

If there are indications that a “conn” parameter is configured for a tunnel, ask the System Administrator (SA) if the tunnel is documented with the ISSO. If “libreswan” is installed, “IPsec” is active, and an undocumented tunnel is active, this is a finding.

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




RHEL-07-040860 - The system must not forward IPv6 source-routed packets.
------------------------------------------------------------------------

Severity
~~~~~~~~

Medium

Description
~~~~~~~~~~~

Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router.

Check
~~~~~

Verify the system does not accept IPv6 source-routed packets.

Note: If IPv6 is not enabled, the key will not exist, and this is not a finding.

Check the value of the accept source route variable with the following command:

# /sbin/sysctl -a | grep  net.ipv6.conf.all.accept_source_route
net.ipv6.conf.all.accept_source_route=0

If the returned lines do not have a value of “0”, a line is not returned, or the retuned line is commented out, this is a finding.

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


