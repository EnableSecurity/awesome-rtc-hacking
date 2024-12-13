# Awesome Real-time Communications Security [![Awesome](https://awesome.re/badge-flat2.svg)](https://awesome.re)

A curated list of Real-time Communications (RTC) security resources focused on VoIP, WebRTC and VoLTE penetration testing, security research and vulnerability assessment.

## Latest Updates

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
- [Related lists](#related-lists)

## Newsletters

- [RTCSec Newsletter](https://www.enablesecurity.com/newsletter/)

## Presentation Slides

- [Hacking VoIP Exposed](https://www.blackhat.com/presentations/bh-usa-06/BH-US-06-Endler.pdf) from Black Hat USA 2006.
- [Mobile network hacking – All-over-IP edition](https://i.blackhat.com/eu-19/Wednesday/eu-19-Yazdanmehr-Mobile-Network-Hacking-IP-Edition-2.pdf) from SRLabs at Blackhat EU 2019
- [Monitoring SIP Traffic Using Support Vector Machines](presentations/Monitoring_SIP_Traffic_Using_Support_Vector_Machines.pdf)

## Videos

- [OpenSSL DoS (CVE-2022-0778) versus WebRTC infrastructure](https://youtu.be/A-2lYuPjAI0)
- [TAD Summit EMEA Americas 2020: Getting offensive: a different approach to RTC security - Sandro Gauci](https://www.youtube.com/watch?v=je959kV-MrY)
- [HITBHaxpo D1: VoLTE Phreaking - Ralph Moonen](https://www.youtube.com/watch?v=H8vo56vImU4)
- [Kamailio World 2019: The Various Ways Your RTC May Be Crushed - Sandro Gauci](https://www.youtube.com/watch?v=012U3NeTVlY)
- [Kamailio World 2018: A tale of two RTC fuzzing approaches - Sandro Gauci](https://www.youtube.com/watch?v=CuxKD5zljVI)
- [Kamailio World 2017: Listening By Speaking - Security Attacks On Media Servers And RTP Relays - Sandro Gauci](https://www.youtube.com/watch?v=cAia1owHy68)
- [Kamailio World 2016: 9 Years Of Friendly Scanning And Vicious SIP - Sandro Gauci](https://www.youtube.com/watch?v=UC3m1PuCFE0)
- [Kamailio World 2015: VoIP Security – Bluebox ng Continuous Pentesting - Sergio García Ramos](https://www.youtube.com/watch?v=9OSvqjxMZBs&t=74s)
- [Kamailio World 2013: VoIP Security Tools - Anton Roman](https://www.youtube.com/watch?v=NToh90VW4LM)
- [Blackhat EU 2019: Mobile network hacking - All-over-IP edition - Karsten Nohl, Luca Melette & Sina Yazdanmehr](https://www.youtube.com/watch?v=3XUo7UBn28o)
- [Jailbreak Brewing Company Security Summit: Whatsup with WhatsApp: A Detailed Walk Through of Reverse Engineering CVE-2019-3568 - Maddie Stone](https://vimeo.com/377181218)
- [RhurSec 2016: Eavesdropping on WebRTC Communication - Martin Johns](https://www.youtube.com/watch?v=3K-BwDGdmko)
- [Hak5 1813: SSL Hack Workarounds and WebRTC Flaws](https://www.youtube.com/watch?v=2a-ry2v29NY)
- [media.ccc.de: WebRTC Security - Stephan Thamm](https://www.youtube.com/watch?v=YOAhq37wdYU) (language: german)

## Advisories

- [Cisco IOS and IOS XE SIP Protocol Denial of Service Vulnerability](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-sip-dos)
- [Cisco IOS XE Software NAT SIP Application Layer Gateway Denial of Service Vulnerability](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-sip-alg)
- [Cisco TelePresence Video Communication Server SIP DoS Vulnerability](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140122-vcs)
- [Voice over LTE implementations contain multiple vulnerabilities](https://www.kb.cert.org/vuls/id/943167/)
- [Asterisk RTP Bleed](https://github.com/EnableSecurity/advisories/tree/master/ES2017-04-asterisk-rtp-bleed)
- [Asterisk pjSIP CSeq Overflow](https://github.com/EnableSecurity/advisories/tree/master/ES2017-01-asterisk-pjsip-cseq-overflow)
- [Juniper Junos Router OS DoS](https://www.cisecurity.org/advisory/a-vulnerability-in-juniper-junos-os-could-allow-for-denial-of-service_2019-111/)
- [Remote Access VPN and SIP Vulnerabilities in Cisco PIX and Cisco ASA](https://www.opennet.ru/base/fire/1220546283_299.txt.html)
- [Interaction SIP Proxy Buffer Overflow in SIPParser() Leads to DoS](https://securitytracker.com/id?1015392)
- [Asterisk pjSIP Multi Parser Out-of-Bound Memory Access](https://github.com/EnableSecurity/advisories/tree/master/ES2017-02-asterisk-pjsip-multi-part-crash)
- [Asterisk Skinny Memory Exhaustion](https://github.com/EnableSecurity/advisories/tree/master/ES2017-02-asterisk-pjsip-multi-part-crash)
- [Asterisk Stack Corruption in `subscribe` Message](https://github.com/EnableSecurity/advisories/tree/master/ES2018-01-asterisk-pjsip-subscribe-stack-corruption)
- [Asterisk Segfault with Invalid SDP `fmtp` Attribute](https://github.com/EnableSecurity/advisories/tree/master/ES2018-02-asterisk-pjsip-sdp-invalid-fmtp-segfault)
- [Asterisk Segfault with Invalid Media Format Descriptiom](https://github.com/EnableSecurity/advisories/tree/master/ES2018-03-asterisk-pjsip-sdp-invalid-media-format-description-segfault)
- [Asterisk Segfault with `INVITE` Replay Attack](https://github.com/EnableSecurity/advisories/tree/master/ES2018-04-asterisk-pjsip-tcp-segfault)
- [Kamalio Off-By-One Heap Overflow](https://github.com/EnableSecurity/advisories/tree/master/ES2018-05-kamailio-heap-overflow)
- [New RCS technology exposes most mobile users to hacking](https://srlabs.de/bites/rcs-hacking/)
- [Zoom Communications user enumeration](https://blog.talosintelligence.com/2020/04/zoom-user-enumeration.html)

## Open-source tools

- [SIPVicious OSS](https://github.com/EnableSecurity/sipvicious/) - A set of tools to audit SIP based systems
- [SIPPTS](https://github.com/Pepelux/sippts) - Another set of tools to audit VoIP servers and devices using SIP protocol.
- [bluebox-ng](https://github.com/jesusprubio/bluebox-ng) - Pentesting framework using Node.js powers, focused in VoIP. (public archive)
- [SigPloit](https://github.com/SigPloiter/SigPloit) - Tool which covers all used SS7, GTP (3G), Diameter (4G) or even SIP protocols for IMS and VoLTE infrastructures.
- [vsaudit](https://github.com/eurialo/vsaudit) - VoIP security assessment framework.
- [rtpnatscan](https://github.com/kapejod/rtpnatscan) - Tool which tests for [rtpbleed](http://rtpbleed.com) vulnerability.
- [VIPROY](https://github.com/fozavci/viproy-voipkit) - VoIP pentest framework which can be used with the metasploit-framework.
- [SIP Proxy](https://sourceforge.net/projects/sipproxy/) - A VoIP security testing tool.
- [Metasploit auxiliary modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/voip)
- [SIPp](http://sipp.sourceforge.net/): SIP based test tool / traffic generator.
    - [SIPp digest leak scenario](http://tomeko.net/other/sipp/sipp_cheatsheet.php)
- [Mr.SIP](https://github.com/meliht/Mr.SIP) - SIP based audit and attack tool.
- [VoIPShark](https://github.com/pentesteracademy/voipshark) - Open Source VoIP Analysis Platform
- [Turner](https://github.com/staaldraad/turner) - PoC for tunnelling HTTP over a permissive/open TURN server.
- [sipsak](https://github.com/nils-ohlmeier/sipsak) - SIP swiss army knife, has some features that can be used for security testing (e.g. flood more or random mode)
- [turnproxy](https://github.com/trichimtrich/turnproxy/) - Tool to abuse open TURN relays
- [SeeYouCM Thief](https://github.com/trustedsec/SeeYouCM-Thief) - download and parse configuration files from Cisco phone systems searching for SSH credentials
- [stunner](https://github.com/firefart/stunner) -  a tool to test and exploit STUN, TURN and TURN over TCP servers.
- [VoIP Hopper](https://github.com/iknowjason/voiphopper) - a tool to exploit insecure VLANs that are often found in IP Telephony infrastructure.

## Papers

- [Abusing SIP Authentication](https://www.researchgate.net/publication/4377144_Abusing_SIP_authentication)
- [Multiple Design Patterns for Voice over IP (VoIP) Security](https://ieeexplore.ieee.org/document/1629443)
- [Realtime Steganography with RTP](http://www.uninformed.org/?v=8&a=3&t=pdf) ([local copy](papers/Realtime_Steganography_with_RTP.pdf))
- [A Lossless Steganography Technique for G.711 Telephony Speech](https://eprints.lib.hokudai.ac.jp/dspace/bitstream/2115/39690/1/MP-P2-7.pdf)
- [CallRank: Combating SPIT Using Call Duration, SocialNetworks and Global Reputation](https://faculty.cc.gatech.edu/~hpark/papers/CallRank.pdf)
- [Steganography of VoIP streams](https://arxiv.org/pdf/0805.2938v1)
- [Steganalysis of compressed speech to detect covert VoIP channels](https://repository.uwl.ac.uk/id/eprint/3959/1/Steganalysis%20of%20compressed%20speech%20to%20detect%20covert%20Voice%20over%20Internet%20Protocol%20channels.pdf)
- [Securing Voice over Internet Protocol](https://annals-csis.org/proceedings/2007/pliks/16.pdf)
- [Protecting SIP Proxy Servers from Ringing-based Denial-of-Service Attacks](https://core.ac.uk/download/pdf/4820112.pdf)
- [An ontology description for SIP security flaws](https://web.archive.org/web/20121222012028/http://www.cs.columbia.edu/~dgen/papers/journal/Journal-03.pdf)
- [Analysis of DDoS Attacks in Heterogeneous VoIP Networks: A Survey](https://www.ijitee.org/wp-content/uploads/papers/v8i6s3/F10490486S319.pdf)
- [Network security systems to counter SIP-based denial-of-service attacks](https://web.archive.org/web/20180619110044/http://www.cs.columbia.edu:80/~dgen/papers/journal/Journal-08.pdf)
- [Multilayer Secured SIP Based VoIP Architecture](https://www.researchgate.net/profile/Rowayda_Sadek/publication/282624359_Multilayer_Secured_SIP_Based_VoIP_Architecture/links/57c3ed2a08aed010b7ee370f/Multilayer-Secured-SIP-Based-VoIP-Architecture.pdf)
- [Battling Against DDoS in SIP](https://www.researchgate.net/profile/Georgios_Kambourakis/publication/281240581_Battling_Against_DDoS_in_SIP_Is_Machine_Learning-based_Detection_an_Effective_Weapon/links/55dc7f2508aec156b9b1801d/Battling-Against-DDoS-in-SIP-Is-Machine-Learning-based-Detection-an-Effective-Weapon.pdf)
- [Billing Attacks on SIP-Based VoIP Systems](https://www.usenix.org/legacy/events/woot07/tech/full_papers/zhang/zhang.pdf)
- [Secure SIP: A Scalable Prevention Mechanism for DoS Attacks on SIP Based VoIP Systems](http://www.cs.columbia.edu/~hgs/papers/Orma0807_Secure.pdf)
- [An Analysis of Security Threats and Tools in SIP-Based VoIP Systems](http://startrinity.com/VoIP/Resources/sip371.pdf)
- [Fast Detection of Denial-of-ServiceAttacks on IP Telephony](https://www.eecis.udel.edu/~hnw/paper/iwqos06.pdf)
- [VoIP Security: Threat Analysis & Countermeasures](https://fysarakis.com/uploads/2/0/6/3/20637656/MSc_Project_Thesis_VoIP.pdf) ([local copy](papers/Threat_Analysis_VoIP_Systems.pdf))
- [Voice Over IP - Security and SPIT](http://www.rainer.baumann.info/public/voip.pdf)

## Blogs

- [Enable Security Blog](https://www.enablesecurity.com/blog/) - A blog about VoIP, WebRTC and real-time communications security by Enable Security
- [Pepelux blog](https://blog.pepelux.org/) (Spanish)
- [Kwancro - Thoughts, tips and tricks](https://www.kwancro.com/) - Often covers SIP honeypot activity and related security topics
- [Fred Posner's Blog](https://www.fredposner.com/) - includes commentary on VoIP security topics

## Notable blog posts and articles

- [Understanding DTLS Usage in VoIP Communications](https://www.gremwell.com/node/954)
- [How we abused Slack's TURN servers to gain access to internal services](https://www.enablesecurity.com/blog/slack-webrtc-turn-compromise-and-bug-bounty/)
- [Analyzing WhatsApp Calls with Wireshark, radare2 and Frida](https://medium.com/@schirrmacher/analyzing-whatsapp-calls-176a9e776213)
- [Adventures in Video Conferencing Part 1: The Wild World of WebRTC](https://googleprojectzero.blogspot.com/2018/12/adventures-in-video-conferencing-part-1.html)
- [Adventures in Video Conferencing Part 2: Fun with FaceTime](https://googleprojectzero.blogspot.com/2018/12/adventures-in-video-conferencing-part-2.html)
- [Adventures in Video Conferencing Part 3: The Even Wilder World of WhatsApp](https://googleprojectzero.blogspot.com/search?q=Adventures+in+Video+Conferencing)
- [Adventures in Video Conferencing Part 4: What Didn't Work Out with WhatsApp](https://googleprojectzero.blogspot.com/2018/12/adventures-in-video-conferencing-part-4.html)
- [Adventures in Video Conferencing Part 5: Where Do We Go from Here?](https://googleprojectzero.blogspot.com/2018/12/adventures-in-video-conferencing-part-5.html)
- [Exploiting CVE-2022-0778, a bug in OpenSSL vis-à-vis WebRTC platforms](https://www.enablesecurity.com/blog/exploiting-cve-2022-0778-in-openssl-vs-webrtc-platforms/)
- [Analyzing two FreeSWITCH vulnerabilities – CVE-2021-41157 & CVE-2021-37624](https://0xinfection.github.io/posts/analyzing-freeswitch-vulns/)
- [Abusing Microsoft Teams Direct Routing](https://blog.syss.com/posts/abusing-ms-teams-direct-routing/)
- [Kamailio’s exec module considered harmful](https://www.enablesecurity.com/blog/kamailio-exec-module-considered-harmful/)

## Books

- [Hacking Exposed Unified Communications & VoIP Security Secrets & Solutions, Second Edition 2nd Edition](https://www.amazon.com/Hacking-Exposed-Communications-Security-Solutions-ebook/dp/B00EHIEDW2/) (published December 20, 2013)
- [Hacking VoIP: Protocols, Attacks, and Countermeasures](https://www.amazon.com/Hacking-VoIP-Protocols-Attacks-Countermeasures-ebook/dp/B004OEJN9C/ref=sr_1_1?sr=8-1) (published March 21, 2008)
- [SIP Security](https://www.amazon.com/dp/0470516364/) (published April 27, 2009)

## Vulnerabilities

The following are generic or common vulnerabilities that are related to either signalling, media or infrastructure.

- [RTP bleed](https://rtpbleed.com)
- [SIP Digest Leak](https://resources.enablesecurity.com/resources/sipdigestleak-tut.pdf)

## CTFs and Learning Resources

- [SIPVicious PRO demo server](https://demo.sipvicious.pro) - Live environment for testing RTC attacks
- [CSAW CTF Qualification Round 2020 / Tasks / WebRTC](https://ctftime.org/task/13011) - CTF challenge featuring WebRTC (2020)

## Related lists

- [Awesome Cellular Hacking](https://github.com/W00t3k/Awesome-Cellular-Hacking)
- [Awesome RTC](https://github.com/rtckit/awesome-rtc/)
- [Awesome Telco](https://github.com/ravens/awesome-telco)
