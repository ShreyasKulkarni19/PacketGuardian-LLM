# PacketGuardian-LLM

The fast-paced evolution of cyber threats poses significant challenges in the field of network security as the attackers are increasingly exploiting vulnerabilities in web applications and network protocols. Common methods like SQL injection, Cross-Site Scripting (XSS), and command injection remain prevalent due to their effectiveness in getting into the systems through seemingly normal network traffic. While traditional intrusion detection systems and packet filters like Snort and Suricata, rely heavily on rule-based and signature-based methods to identify malicious patterns, these approaches struggle to adapt to complex attacks, leaving gaps in real-time defense mechanisms.
In this project, we present PacketGuardian-LLM, a proof of concept network packet analyzer that uses pre-trained generative models via API’s to detect SQL injections, XSS, and command injection attacks within HTTP traffic captured using tools like Wireshark and stored as PCAP files. Unlike the conventional systems, PacketGuardian-LLM uses rule-based preprocessing along with LLM-driven analysis to examine the payload and the header. By analyzing Wireshark logs, the approach identifies malicious patterns while giving a good explanation, making it easier to analyze the threats. The work is intended to demonstrate the potential of LLMs to augment network security, improving the automated threat detection in a fast changing digital landscape.


-- Project Schedule --
Mar 25, 2025 (Planning and Setup): Initial Planning, Data and project design
Apr 17, 2025 (Core development): Payload analysis, Header analysis, Preprocessing layer
Apr 29, 2025: Testing and Demo preparation


References
[1] Zhang, Xinye & Chai, Xiaoli & Yu, Minghua & Qiu, Ding. (2023). Anomaly Detection Model for Log Based on LSTM Network and Variational Autoencoder. 239-244. 10.1109/ISPDS58840.2023.10235370. 
[2] Aoxiao Zhong, Dengyao Mo, Guiyang Liu, Jinbu Liu, Qingda Lu, Qi Zhou, Jiesheng Wu, Quanzheng Li, and Qingsong Wen. 2024. LogParser-LLM: 45 Advancing Efficient Log Parsing with Large Language Models. In Proceedings of the 30th ACM SIGKDD Conference on Knowledge Discovery and Data Mining. 4559–4570. 
[3]  Prasasthy Balasubramanian, Justin Seby, and Panos Kostakos. 2023. Transformer-based llms in cybersecurity: An in-depth study on log anomaly detection and conversational defense mechanisms. In 2023 IEEE International Conference on Big Data (BigData). IEEE, 3590–3599
