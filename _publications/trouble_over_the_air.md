---
title: "Trouble Over-The-Air: An analysis of FOTA Apps in the Android Ecosystem"
excerpt: "42nd IEEE Symposium on Security and Privacy. March 2021"
sidebar:
    - title: "Authors"
      text: "Eduardo Blázquez, Sergio Pastrana, Álvaro FEAL, Julien GAMBA, Platon Kotzias, Narseo VALLINA-RODRÍGUEZ, Juan Tapiador"
    - title: "Link to paper"
      text: "https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1t0x9wqtFAI/pdf"
---

Introduction 1 minute video: [Trouble Over-The-Air: An Analysis of FOTA Apps in the Android Ecosystem](https://www.youtube.com/watch?v=P25oExrqg94)

Talk: [Trouble Over-The-Air: An Analysis of FOTA Apps in the Android Ecosystem](https://www.youtube.com/watch?v=b7AwsSVKz1k) (you can activate subs in English)

## Abstract

Android firmware updates are typically managed by the so-called FOTA (Firmware Over-the-Air) apps. Such apps are highly privileged and play a critical role in maintaining devices secured and updated. The Android operating system offers standard mechanisms—available to Original Equipment Manufacturers (OEMs)—to implement their own FOTA apps but such vendor-specific implementations could be a source of security and privacy issues due to poor software engineering practices. This paper performs the first large-scale and systematic analysis of the FOTA ecosystem through a dataset of 2,013 FOTA apps detected with a tool designed for this purpose over 422,121 pre-installed apps. We classify the different stakeholders developing and deploying FOTA apps on the Android update ecosystem, showing that 43% of FOTA apps are developed by third parties. We report that some devices can have as many as 5 apps implementing FOTA capabilities. By means of static analysis of the code of FOTA apps, we show that some apps present behaviors that can be considered privacy intrusive, such as the collection of sensitive user data (e.g., geolocation linked to unique hardware identifiers), and a significant presence of third-party trackers. We also discover implementation issues leading to critical vulnerabilities, such as the use of public AOSP test keys both for signing FOTA apps and for update verification, thus allowing any update signed with the same key to be installed. Finally, we study telemetry data collected from real devices by a commercial security tool. We demonstrate that FOTA apps are responsible for the installation of non-system apps (e.g., entertainment apps and games), including malware and Potentially Unwanted Programs (PUP). Our findings suggest that FOTA development practices are misaligned with Google’s recommendations.

## Bibtex

```
@inproceedings{blazquez2021fota,
  author    = {E. Bl\'azquez and S. Pastrana and \'A. Feal and J. Gamba and P. Kotzias and N. Vallina-Rodriguez and J. Tapiador},
  booktitle = {2021 2021 IEEE Symposium on Security and Privacy (SP)},
  title     = {Trouble Over-the-Air: An Analysis of FOTA Apps in the Android Ecosystem},
  year      = {2021},
  volume    = {},
  issn      = {2375-1207},
  pages     = {1641-1657},
  keywords  = {privacy;security;android;supply-chain;updates},
  doi       = {10.1109/SP40001.2021.00095},
  url       = {https://doi.ieeecomputersociety.org/10.1109/SP40001.2021.00095},
  publisher = {IEEE Computer Society},
  address   = {Los Alamitos, CA, USA},
  month     = {may}
}
```