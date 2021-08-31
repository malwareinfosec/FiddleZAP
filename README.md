# FiddleZAP

FiddleZAP is a simplified version of [EKFiddle](https://github.com/malwareinfosec/EKFiddle) for OWASP ZAP written for the Graal.js engine.

# Installation

- Download and install ZAP: https://www.zaproxy.org/download/

- Download or clone the FiddleZAP directory into your Documents folder.

It should have the following structure:



- Click on the Load script icon: 

![image](https://user-images.githubusercontent.com/25351665/131580293-a2a603ad-c723-4c5d-b19b-3ee9c99a8480.png)

- Select the following parameters:

![image](https://user-images.githubusercontent.com/25351665/131580345-04c22bb1-ba30-4622-ba50-01e1ac6136fa.png)

The FiddleZAP script should now show up under Passive Rules. If it is not enabled, right-click on it and select Enable script.

![image](https://user-images.githubusercontent.com/25351665/131580409-0e58660b-96cc-4373-b94b-d2bcb316d2de.png)


# Features

## Regexes (rules) to detect malicious traffic

Rules for FiddleZAP can look for URI patterns and source code patterns (session body).

- A ``community_rules.txt`` file is provided with some examples.

- The ``user_rules.txt`` is your own rules file.


## Color coding and tagging of matching web sessions

(This feature requires the neonmarker add-on)

![image](https://user-images.githubusercontent.com/25351665/131417750-d06aa169-c862-4daa-abb9-55d941ea98a6.png)

## Detailed alerts

![image](https://user-images.githubusercontent.com/25351665/131417845-5289925e-573a-4eef-b42b-cf406ff9e9bb.png)


