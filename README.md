# Awesome Real-time Communications Security [![Awesome](https://awesome.re/badge-flat2.svg)](https://awesome.re)

A curated list of Real-time Communications (RTC) security resources focused on VoIP, WebRTC and VoLTE penetration testing, security research and vulnerability assessment.

## Latest Updates

- 2025-07: Add new advisories (CVE ‑2023 ‑7024, CVE ‑2024 ‑35190, CVE ‑2024 ‑42491), updated broken Cisco links and removed dead references; added new blog posts (DTLS “ClientHello” race conditions, novel DoS vulnerability in WebRTC media servers, TADSummit podcast review) and added a new video from OWASP Global AppSec 2024.
- 2024-12: Updated broken links and references
- 2024-12: Add new blogs

## Contributing

Your contributions are always welcome! Please read the contribution guidelines first:

- Check if the resource is still active/available
- Add a short description for tools and papers
- Include publication dates where applicable
- Keep descriptions concise and clear
- Sort entries alphabetically within sections
- Check your spelling and grammar
- Make sure your text editor is set to remove trailing whitespace

## License

[![CC0](https://licensebuttons.net/p/zero/1.0/88x31.png)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, the authors have waived all copyright and related rights to this work.

## Table of Contents

- [Newsletters](#newsletters)
- [Presentation Slides](#presentation-slides)
- [Videos](#videos)
- [Advisories](#advisories)
- [Open-source tools](#open-source-tools)
- [Papers](#papers)
- [Blogs](#blogs)
- [Notable blog posts and articles](#notable-blog-posts-and-articles)
- [Books](#books)
- [Commercial tools](#commercial-tools)
- [Vulnerabilities](#vulnerabilities)
- [CTFs and Learning Resources](#ctfs-and-learning-resources)
- [Related lists](#related-lists)

## Newsletters

- [RTCSec Newsletter](https://www.enablesecurity.com/newsletter/)

## Presentation Slides

- [Hacking VoIP Exposed](https://www.blackhat.com/presentations/bh-usa-06/BH-US-06-Endler.pdf) – Black Hat USA 2006.
- [Mobile network hacking – All-over-IP edition](https://i.blackhat.com/eu-19/Wednesday/eu-19-Yazdanmehr-Mobile-Network-Hacking-IP-Edition-2.pdf) – SRLabs at Black Hat EU 2019.
- [Monitoring SIP Traffic Using Support Vector Machines](presentations/Monitoring_SIP_Traffic_Using_Support_Vector_Machines.pdf)

## Videos

- [Blackhat EU 2019: Mobile network hacking – All‑over‑IP edition – Karsten Nohl, Luca Melette & Sina Yazdanmehr](https://www.youtube.com/watch?v=3XUo7UBn28o)
- [Hak5 1813: SSL Hack Workarounds and WebRTC Flaws](https://www.youtube.com/watch?v=2a-ry2v29NY)
- [HITBHaxpo D1: VoLTE Phreaking – Ralph Moonen](https://www.youtube.com/watch?v=H8vo56vImU4)
- [Jailbreak Brewing Company Security Summit: Whatsup with WhatsApp – A Detailed Walk Through of Reverse Engineering CVE ‑2019 ‑3568 – Maddie Stone](https://vimeo.com/377181218)
- [Kamailio World 2013: VoIP Security Tools – Anton Roman](https://www.youtube.com/watch?v=NToh90VW4LM)
- [Kamailio World 2015: VoIP Security – Bluebox ng Continuous Pentesting – Sergio García Ramos](https://www.youtube.com/watch?v=9OSvqjxMZBs&t=74s)
- [Kamailio World 2016: 9 Years of Friendly Scanning and Vicious SIP](https://www.youtube.com/watch?v=UC3m1PuCFE0)
- [Kamailio World 2017: Listening By Speaking – Security Attacks On Media Servers and RTP Relays – Sandro Gauci](https://www.youtube.com/watch?v=cAia1owHy68)
- [Kamailio World 2018: A tale of two RTC fuzzing approaches – Sandro Gauci](https://www.youtube.com/watch?v=CuxKD5zljVI)
- [Kamailio World 2019: The Various Ways Your RTC May Be Crushed – Sandro Gauci](https://www.youtube.com/watch?v=012U3NeTVlY)
- [media.ccc.de: WebRTC Security – Stephan Thamm (German)](https://www.youtube.com/watch?v=YOAhq37wdYU)
- [OpenSSL DoS (CVE ‑2022 ‑0778) versus WebRTC infrastructure](https://youtu.be/A-2lYuPjAI0)
- [OWASP Global AppSec 2024: Web Security Experts – Are you overlooking WebRTC vulnerabilities? – Sandro Gauci](https://www.youtube.com/watch?v=g-rtvp6CXeI)
- [RhurSec 2016: Eavesdropping on WebRTC Communication – Martin Johns](https://www.youtube.com/watch?v=3K-BwDGdmko)
- [TAD Summit EMEA Americas 2020: Getting offensive – a different approach to RTC security – Sandro Gauci](https://www.youtube.com/watch?v=je959kV-MrY)

## Advisories

- [Asterisk pjSIP CSeq Overflow](https://github.com/EnableSecurity/advisories/tree/master/ES2017-01-asterisk-pjsip-cseq-overflow)
- [Asterisk pjSIP Multi Parser Out‑of‑Bound Memory Access](https://github.com/EnableSecurity/advisories/tree/master/ES2017-02-asterisk-pjsip-multi-part-crash)
- [Asterisk Segfault with `INVITE` Replay Attack](https://github.com/EnableSecurity/advisories/tree/master/ES2018-04-asterisk-pjsip-tcp-segfault)
- [Asterisk Segfault with Invalid Media Format Description](https://github.com/EnableSecurity/advisories/tree/master/ES2018-03-asterisk-pjsip-sdp-invalid-media-format-description-segfault)
- [Asterisk Segfault with Invalid SDP `fmtp` Attribute](https://github.com/EnableSecurity/advisories/tree/master/ES2018-02-asterisk-pjsip-sdp-invalid-fmtp-segfault)
- [Asterisk Stack Corruption in `subscribe` Message](https://github.com/EnableSecurity/advisories/tree/master/ES2018-01-asterisk-pjsip-subscribe-stack-corruption)
- [Asterisk Skinny Memory Exhaustion](https://github.com/EnableSecurity/advisories/tree/master/ES2017-02-asterisk-pjsip-multi-part-crash)
- [CVE ‑2023 ‑7024: Chromium WebRTC heap buffer overflow](https://nvd.nist.gov/vuln/detail/CVE-2023-7024) – A heap buffer overflow in Chromium’s WebRTC component prior to version 120.0.6099.129 allows a remote attacker to cause heap corruption via a crafted HTML page【536784917078941†L117-L125】.
- [CVE ‑2024 ‑35190: Asterisk SIP endpoint misclassification](https://nvd.nist.gov/vuln/detail/CVE-2024-35190) – In Asterisk 18.23.0, all unauthorized SIP requests are treated as PJSIP endpoints, potentially allowing attackers to evade security checks; fixed in versions 18.23.1, 20.8.1 and 21.3.1【413529452339731†L127-L131】.
- [CVE ‑2024 ‑42491: Asterisk crash via malformed SIP URI](https://nvd.nist.gov/vuln/detail/CVE-2024-42491) – A crash occurs when Asterisk receives a SIP request whose URI host starts with `.1` or `[.1]`. Workarounds include disabling `res_resolver_unbound` or setting `rewrite_contact=yes`【275937892890727†L127-L136】.
- [Cisco IOS and IOS XE SIP Protocol Denial of Service Vulnerability](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-sip-dos)
- [Cisco IOS XE Software NAT SIP Application Layer Gateway Denial of Service Vulnerability](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-sip-alg)
- [Cisco TelePresence Video Communication Server SIP DoS Vulnerability](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140122-vcs)
- [Interaction SIP Proxy Buffer Overflow in `SIPParser()` Leads to DoS](https://securitytracker.com/id?1015392)
- [Juniper Junos Router OS DoS](https://www.cisecurity.org/advisory/a-vulnerability-in-juniper-junos-os-could-allow-for-denial-of-service_2019-111/)
- [Kamalio Off‑By‑One Heap Overflow](https://github.com/EnableSecurity/advisories/tree/master/ES2018-05-kamailio-heap-overflow)
- [Remote Access VPN and SIP Vulnerabilities in Cisco PIX and Cisco ASA](https://www.opennet.ru/base/fire/1220546283_299.txt.html)
- [Voice over LTE implementations contain multiple vulnerabilities](https://www.kb.cert.org/vuls/id/943167/)
- [Zoom Communications user enumeration](https://blog.talosintelligence.com/2020/04/zoom-user-enumeration.html)

## Open‑source tools

- [Metasploit auxiliary modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/voip) – Auxiliary VoIP‑related modules for Metasploit.
- [Mr.SIP](https://github.com/meliht/Mr.SIP) – SIP‑based audit and attack tool.
- [SIP Proxy](https://sourceforge.net/projects/sipproxy/) – VoIP security testing tool.
- [SIPPTS](https://github.com/Pepelux/sippts) – Another set of tools to audit VoIP servers and devices using the SIP protocol.
- [SIPVicious OSS](https://github.com/EnableSecurity/sipvicious/) – A set of tools to audit SIP‑based systems.
- [SIPp](http://sipp.sourceforge.net/) – SIP‑based test tool / traffic generator.
  - [SIPp digest leak scenario](http://tomeko.net/other/sipp/sipp_cheatsheet.php)
- [SeeYouCM Thief](https://github.com/trustedsec/SeeYouCM-Thief) – Downloads and parses configuration files from Cisco phone systems searching for SSH credentials.
- [SigPloit](https://github.com/SigPloiter/SigPloit) – Covers SS7, GTP (3G), Diameter (4G) and SIP protocols for IMS and VoLTE infrastructures.
- [Stunner](https://github.com/firefart/stunner) – Tool to test and exploit STUN, TURN and TURN‑over‑TCP servers.
- [Turner](https://github.com/staaldraad/turner) – PoC for tunneling HTTP over a permissive or open TURN server.
- [SeeYouCM Thief](https://github.com/trustedsec/SeeYouCM-Thief) – Downloads and parses configuration files from Cisco phone systems searching for SSH credentials.
- [sipsak](https://github.com/nils-ohlmeier/sipsak) – “Swiss‑army knife” SIP tool with features useful for security testing.
- [turnproxy](https://github.com/trichimtrich/turnproxy/) – Tool to abuse open TURN relays.
- [VoIP Hopper](https://github.com/iknowjason/voiphopper) – Exploits insecure VLANs often found in IP Telephony infrastructure.
- [VoIPShark](https://github.com/pentesteracademy/voipshark) – Open‑source VoIP analysis platform.
- [VIPROY](https://github.com/fozavci/viproy-voipkit) – VoIP pentest framework used with the Metasploit Framework.
- [vsaudit](https://github.com/eurialo/vsaudit) – VoIP security assessment framework.
- [rtpnatscan](https://github.com/kapejod/rtpnatscan) – Tests for the [rtpbleed](http://rtpbleed.com) vulnerability.
- [bluebox‑ng](https://github.com/jesusprubio/bluebox-ng) – Pentesting framework using Node.js, focused on VoIP (public archive).

## Papers

- [Abusing SIP Authentication](https://www.researchgate.net/publication/4377144_Abusing_SIP_authentication)
- [An Analysis of Security Threats and Tools in SIP‑Based VoIP Systems](http://startrinity.com/VoIP/Resources/sip371.pdf)
- [Analysis of DDoS Attacks in Heterogeneous VoIP Networks: A Survey](https://www.ijitee.org/wp-content/uploads/papers/v8i6s3/F10490486S319.pdf)
- [Battling Against DDoS in SIP](https://www.researchgate.net/profile/Georgios_Kambourakis/publication/281240581_Battling_Against_DDoS_in_SIP_Is_Machine_Learning-based_Detection_an_Effective_Weapon/links/55dc7f2508aec156b9b1801d/Battling-Against-DDoS-in-SIP-Is-Machine-Learning-based-Detection-an-Effective-Weapon.pdf)
- [Billing Attacks on SIP‑Based VoIP Systems](https://www.usenix.org/legacy/events/woot07/tech/full_papers/zhang/zhang.pdf)
- [CallRank: Combating SPIT Using Call Duration, Social Networks and Global Reputation](https://faculty.cc.gatech.edu/~hpark/papers/CallRank.pdf)
- [Fast Detection of Denial‑of‑Service Attacks on IP Telephony](https://www.eecis.udel.edu/~hnw/paper/iwqos06.pdf)
- [Multilayer Secured SIP‑Based VoIP Architecture](https://www.researchgate.net/profile/Rowayda_Sadek/publication/282624359_Multilayer_Secured_SIP_Based_VoIP_Architecture/links/57c3ed2a08aed010b7ee370f/Multilayer-Secured-SIP-Based-VoIP-Architecture.pdf)
- [Multiple Design Patterns for Voice over IP (VoIP) Security](https://ieeexplore.ieee.org/document/1629443)
- [Network security systems to counter SIP‑based denial‑of‑service attacks](https://web.archive.org/web/20180619110044/http://www.cs.columbia.edu/~dgen/papers/journal/Journal-08.pdf)
- [Realtime Steganography with RTP](http://www.uninformed.org/?v=8&a=3&t=pdf) ([local copy](papers/Realtime_Steganography_with_RTP.pdf))
- [Securing Voice over Internet Protocol](https://annals-csis.org/proceedings/2007/pliks/16.pdf)
- [Secure SIP: A Scalable Prevention Mechanism for DoS Attacks on SIP‑Based VoIP Systems](http://www.cs.columbia.edu/~hgs/papers/Orma0807_Secure.pdf)
- [Steganalysis of compressed speech to detect covert VoIP channels](https://repository.uwl.ac.uk/id/eprint/3959/1/Steganalysis%20of%20compressed%20speech%20to%20detect%20covert%20Voice%20over%20Internet%20Protocol%20channels.pdf)
- [Steganography of VoIP streams](https://arxiv.org/pdf/0805.2938v1)
- [VoIP Security: Threat Analysis & Countermeasures](https://fysarakis.com/uploads/2/0/6/3/20637656/MSc_Project_Thesis_VoIP.pdf) ([local copy](papers/Threat_Analysis_VoIP_Systems.pdf))

## Blogs

- [Enable Security Blog](https://www.enablesecurity.com/blog/) – VoIP, WebRTC and real‑time communications security research.
- [Fred Posner’s Blog](https://www.fredposner.com/) – Commentary on VoIP security topics.
- [Kwancro – Thoughts, tips and tricks](https://www.kwancro.com/) – Often covers SIP honeypot activity and related security topics.
- [Pepelux blog](https://blog.pepelux.org/) (Spanish)

## Notable blog posts and articles

- [Abusing Microsoft Teams Direct Routing](https://blog.syss.com/posts/abusing-ms-teams-direct-routing/)
- [Analyzing two FreeSWITCH vulnerabilities – CVE ‑2021 ‑41157 & CVE ‑2021 ‑37624](https://0xinfection.github.io/posts/analyzing-freeswitch-vulns/)
- [Analyzing WhatsApp Calls with Wireshark, radare2 and Frida](https://medium.com/@schirrmacher/analyzing-whatsapp-calls-176a9e776213)
- [A Novel DoS Vulnerability affecting WebRTC Media Servers](https://www.enablesecurity.com/blog/novel-dos-vulnerability-affecting-webrtc-media-servers/) – Describes a critical denial‑of‑service vulnerability in WebRTC media servers caused by race conditions between ICE and DTLS traffic and proposes mitigations based on ICE‑validated IP/port filtering【412516447577886†L34-L43】.
- [DTLS “ClientHello” Race Conditions in WebRTC Implementations](https://www.enablesecurity.com/blog/webrtc-hello-race-conditions-paper/) – White paper showing how failing to verify the origin of DTLS ClientHello messages allows denial‑of‑service attacks across multiple platforms like RTPEngine, Asterisk, FreeSWITCH and Skype【165485385753544†L26-L70】.
- [Exploiting CVE ‑2022 ‑0778, a bug in OpenSSL vis‑à‑vis WebRTC platforms](https://www.enablesecurity.com/blog/exploiting-cve-2022-0778-in-openssl-vs-webrtc-platforms/)
- [How we abused Slack’s TURN servers to gain access to internal services](https://www.enablesecurity.com/blog/slack-webrtc-turn-compromise-and-bug-bounty/)
- [Kamailio’s exec module considered harmful](https://www.enablesecurity.com/blog/kamailio-exec-module-considered-harmful/)
- [OpenSIPS Security Audit Report fully disclosed](https://www.enablesecurity.com/blog/open-sips-security-audit-report/) – Summary of the full OpenSIPS security audit report from 2022, including discovered vulnerabilities and fixes【604035037388723†L31-L59】.
- [TADSummit Innovators Podcast: RTC security trends 2024](https://www.enablesecurity.com/blog/tadsummit-innovators-podcast-with-sandro-gauci/) – Podcast episode reviewing VoIP and WebRTC security news from the first half of 2024, highlighting increased focus on WebRTC vulnerabilities, emerging AI threats and the importance of resilience and regular penetration testing【203110641354402†L35-L60】.
- [Understanding DTLS Usage in VoIP Communications](https://www.gremwell.com/node/954)

## Books

- [Hacking Exposed Unified Communications & VoIP Security Secrets & Solutions, Second Edition](https://www.amazon.com/Hacking-Exposed-Communications-Security-Solutions-ebook/dp/B00EHIEDW2/) (2013)
- [Hacking VoIP: Protocols, Attacks, and Countermeasures](https://www.amazon.com/Hacking-VoIP-Protocols-Attacks-Countermeasures-ebook/dp/B004OEJN9C/ref=sr_1_1?sr=8-1) (2008)
- [SIP Security](https://www.amazon.com/dp/0470516364/) (2009)

## Commercial tools

*This section intentionally left blank – please contribute suggestions for commercial RTC security tools!*

## Vulnerabilities

The following are generic or common vulnerabilities related to signaling, media or infrastructure.

- [RTP bleed](https://rtpbleed.com)
- [SIP Digest Leak](https://resources.enablesecurity.com/resources/sipdigestleak-tut.pdf)

## CTFs and Learning Resources

- [CSAW CTF Qualification Round 2020 / Tasks / WebRTC](https://ctftime.org/task/13011) – CTF challenge featuring WebRTC (2020)
- [SIPVicious PRO demo server](https://demo.sipvicious.pro) – Live environment for testing RTC attacks

## Related lists

- [Awesome Cellular Hacking](https://github.com/W00t3k/Awesome-Cellular-Hacking)
- [Awesome RTC](https://github.com/rtckit/awesome-rtc/)
- [Awesome Telco](https://github.com/ravens/awesome-telco)
