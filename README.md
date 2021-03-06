# FiddleZAP

FiddleZAP is a simplified version of [EKFiddle](https://github.com/malwareinfosec/EKFiddle) for OWASP ZAP. 

With ZAP as your web proxy, you are able to flag malicious traffic based on predefined regular expressions.

Example: Alert, highlighting and tagging when a regex matches on a string within the HTML source code of a compromised website

![image](https://user-images.githubusercontent.com/25351665/132754774-bd5278ee-dad4-4107-bfa5-472b777fd52e.png)

![image](https://user-images.githubusercontent.com/25351665/132754478-ad225161-0f66-4cc7-903b-73c89817e737.png)

# Installation

- Download and install ZAP: https://www.zaproxy.org/download/

- Download or clone the FiddleZAP directory into your Documents folder.

It should have the following structure:

![image](https://user-images.githubusercontent.com/25351665/132750706-3965d2cb-5834-4144-bd15-3115c0dd3a67.png)

![image](https://user-images.githubusercontent.com/25351665/132750818-9ec7bbea-deff-41b0-abac-15b645768e57.png)

There are 2 scripts (standalone, passive rules). The former is used to run manually on the currently loaded session (web traffic), the latter automatically runs while recording traffic.

## Stand Alone

First, install the standalone script:

- Click on the Load script icon:

![image](https://user-images.githubusercontent.com/25351665/132749274-64f83b76-6c01-4121-b934-3d0621c4b628.png)

- Select the following parameters:

![image](https://user-images.githubusercontent.com/25351665/132750572-7cfa0fdd-9204-4d12-8c1e-7250c87c7577.png)

- It now shows under standalone:

![image](https://user-images.githubusercontent.com/25351665/132749556-ae47b44b-d595-4e51-9ee4-f86815eeaf9b.png)

## Passive Rules

Next, install the passive rules script:

- Click on the Load script icon:

![image](https://user-images.githubusercontent.com/25351665/132749999-418b061f-78fd-4b5b-9890-eb3316d5605c.png)

- Select the following parameters:

![image](https://user-images.githubusercontent.com/25351665/132750390-4789935d-cc73-4f6f-a6b0-3f251d5bd72c.png)

The FiddleZAP script should now show up under Passive Rules. If it is not enabled, right-click on it and select Enable script.

![image](https://user-images.githubusercontent.com/25351665/132750118-f2a792d4-c8ec-478f-aba2-55cf8c85c122.png)

# Features

## Regexes (rules) to detect malicious traffic

Rules for FiddleZAP can look for URI patterns and source code patterns (session body).

- A ``community_rules.txt`` file is provided with some examples.

- The ``user_rules.txt`` is your own rules file.

Rules are automatically loaded and used to scan incoming traffic (if Passive Rules script is enabled). If you want to run rules on previously captured traffic, you need to run the standalone script.

![image](https://user-images.githubusercontent.com/25351665/132890280-e1322936-38f8-4735-b003-b27a8c166c87.png)

## Color coding and tagging of matching web sessions

(This feature requires the neonmarker add-on)

![image](https://user-images.githubusercontent.com/25351665/131417750-d06aa169-c862-4daa-abb9-55d941ea98a6.png)

## Detailed alerts

![image](https://user-images.githubusercontent.com/25351665/131417845-5289925e-573a-4eef-b42b-cf406ff9e9bb.png)


