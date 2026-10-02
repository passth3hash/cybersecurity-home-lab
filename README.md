# Cybersecurity Home Lab 

An isolated home laboratory for learning and practicing cybersecurity, network reconnaissance and web application penetration testing.

## Project Overview

This project documents the design, deployment and security testing of an isolated virtual cybersecurity laboratory.

The initial lab focuses on performing a controlled penetration test against OWASP Juice Shop, a deliberately vulnerable web application designed for security training.

## Objectives

The objective is to develop practical skills in:

- Virtual network isolation
- Linux administration
- Docker
- Network reconnaissance
- Web application enumeration
- Vulnerability identification and validation
- Security testing methodology
- Evidence collection
- Technical security reporting
- Remediation recommendations

## Lab Architecture 

                         Windows Host
                              │
                         VirtualBox
                              │
              ┌───────────────┴───────────────┐
              │                               │
        Kali Linux                       Ubuntu Server
         Attacker                            Target
     192.168.56.101                     192.168.56.102
              │                               │
              └────── Host-Only Network ──────┘
                    192.168.56.0/24
                                              │
                                            Docker
                                              │
                                    OWASP Juice Shop
                                      192.168.56.102:3000


### Architecture Overview 

This lab is built on a Windows hosting Oracle VirtualBox to create an isolated virtual environment for cybersecurity testing. 

The environment consists of two virtual machines: Kali Linux, which servers as the attacker machine and Ubuntu Server, which serves as the target system. Both virtual machines communicate through a dedicated VirtualBox Host-Only Network, keeping the testing environment separate from the physical home network.

Ubuntu Server hosts Docker, which runs the intentionally vulnerable OWASP Juice Shop web application. 

This architecture provides a controlled environment where reconnaissance and web application security testing can be performed without intentionally exposing the vulnerable application to the Internet.

### Network Design 

During the initial Ubuntu Server setup, I learned that a NAT adapter can temporarily provide a virtual machine with Internet connectivity through the host system. I used NAT for system updates, Docker installation, and downloading the OWASP Juice Shop image.

Once the setup was complete, I disabled NAT on Ubuntu and kept only the Host-Only adapter enabled for security testing.

1. **NAT - Let this VM get out**
   
- The VM can access the Internet through the Windows host's network connection.
- I used NAT on Ubuntu to download system updates, install Docker, and download the Juice Shop image.

2. **Host-Only - Let these lab machines talk to each other**
   
- The VM can communicate with the Windows host and other VMs on the Host-Only network.
- Host-Only networking does not provide Internet access by itself.
- In my lab, Kali can communicate with Ubuntu and Juice Shop, while Ubuntu has no default route to the Internet.

3. **Network Verification**
   
- After disabling NAT, I used `ip route` on Ubuntu to verify that there was no default route to the Internet, so Ubuntu could not reach hosts outside the           isolated lab network.
- From Kali, I used `curl` to access Juice Shop on Ubuntu, confirming that the application remained reachable through the Host-Only network.

## Technologies 

- Windows
- Kali Linux
- Oracle VirtualBox 
- Ubuntu Server
- Docker 
- Owasp Juice Shop 
- VirtualBox Host-Only Networking 

  
    



