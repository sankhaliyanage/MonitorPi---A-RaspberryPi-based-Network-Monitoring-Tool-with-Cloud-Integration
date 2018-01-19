# MonitorPi---A-RaspberryPi-based-Network-Monitoring-Tool-with-Cloud-Integration
A RaspberryPi based Network Monitoring Tool with Real-Time Cloud Integration 
Project Outline

3.1 Scope
The tool is specifically developed to identify packets, ICMP and SYN flood-attacks within the Local Area Network. The proposed tool will run on a Raspberry Pi and capture data frames, analyze the packet types and detect any abnormalities through a wired Ethernet interface running on (IEEE 802.3 standard). Apart, the tool has added functionality to check individual device status (by sending ping requests) and record delay and jitter of each device. All the recorded data will be uploaded to a MQTT Broker, where the network administrators are given the privilege to view the network activity over cloud. The proposed tool will be implemented for LAN usage and the created features will be focused on LAN specifications. 

3.2 Assumptions 
•	The following assumptions were made by the author to keep the project within the defined scope. 
•	The implemented application functionality is defined strictly for IPv4 Local Area Networks
•	The device can read/write to/from the network and is connected to a port with LAN port/packet-mirroring ability; where the network-end and the proposed system-end operates in promiscuous mode. (receive all the packets regardless of the sender and recipient).  
•	The output results are displayed in a GUI and on a MQTT Web-dashboard. 


3.3 Constraints
Considering the limited testing resources available, constraints were imposed on the system which can be elevated for future development and added resources. 
The application is designed to run on Debian Linux based platform with Python and PyQt support. The API supports multiple platforms including Android/Unix and Windows; which can be run using LibPcap library. 
The application doesn’t support Python backward compatibility and requires the exact same resources and libraries for the functionality of the application.
The application is limited to IPv4 packet analysis; no IPv6 support is provided for the application at the defined level.  

3.4 Solution Concept
Considering the Problem Overview and Similar tools available in the market, the primary concern was to implement a LAN monitoring tool with added portability. After considering the main contenders, the tool was planned to implement on Raspberry Pi as the device has to be prioritized only for packet analysis process. Linux provide open-source Operating System and all the required libraries for free. The above decision was made over Android mobile devices as they lack an Ethernet port; which matter when using a serial Ethernet bridge to strip the incoming packet for IP address and MAC address rendering process. The tool sniffs packet headers via a socket. Python can be used for packet capturing services as ‘Pycap’ libraries and scripting provides the full-functionality to implement the required services.
Apart from packet analysis, the proposed tool will have added functionality to identify active devices by sending periodic ping requests to the devices in the network. By calculating the Delay and Jitter, the network administrators would be able to further optimize the system for efficient functionality. All the data will be uploaded to a MQTT Broker and displayed on a web-dashboard; thus, enabling the administrators to view the network activity without remote login to the system. Implementing the proposed system would enable the administrator to remotely monitor the network activity and easily compensate during a network attack with minimal damage to the company.  

5.2 Software Requirements

The default Raspbian Jessie was replaced with Raspbian Jessie Lite operating system as the implemented system is highly resource-intensive. Compared to Raspbian Jessie, Raspbian Jessie Lite lacks X-Server and its respective components. A very light Graphical User Interface is used to ease user involvement with the device. The program is designed to implement in Python as it is a very-powerful, versatile programming language running on devices with minimal resources. 
Components

6.1 Monitoring Tool to detect Internal Attacks

6.1.1 Functionality
The application involves in identifying network packets at OSI Layer 2 and 3. The process involves in socket implementation and packet header disassembly for packet-type identification. The counted packets are displayed on a Graphical User Interface and a counter involves in identifying sudden surges of a specific packet-type; helping to identify unusual network activity in return. The read packets are categorized by the source MAC address over IP addresses as IP addresses can be spoofed easily compared to MAC address.  However, the application only checks for the source MAC address. To gain the full functionality, the source and destination MAC addresses tracing can be added to the application; which would enable the network administrators to easily identify the rogue device. 


6.1.2 Software Architecture Diagram

6.2 Network Activity Monitoring

6.2.1 Functionality
The second component of the application involves in applying the monitoring tool to a fully operational industrial scale network; where the network activity is monitored using the Raspberry Pi. The proposed system will monitor the ping, delay, jitter and load of each networking device. The functionality and application of each component is explained below.
Ping checks the reachability status of a network component by sending ICMP request -reply packets. By monitoring Ping requests, the network administrators gain the ability to identify inactive/faulty devices and would make it easier to troubleshoot. 
Delay defines the time taken for 1-bit to travel from the source to the destination. The delay is measured in milliseconds and significantly affects QoS on VoIP networks. By monitoring the delay, network engineers can analyze the devices with highest traffic (higher delay compared to average network delay) and opens the opportunity to increase the efficiency of the network by implementing new routes and algorithms.  
Jitter is the variation in delivery of packet-order during a network packet transmission. The packets take multiple paths (where paths vary from packet to packet depending on the best path available) due to queuing, configuration errors and network congestion. The packets are sent from the source port with defined time intervals; but the packets may receive at the destination with variable time gaps due to multiple path selection. Jitter significantly affects video and data streaming networks; the analysis can increase the efficiency and overall productivity of the network.  

6.3 Upload & Display the sensor data on a MQTT Broker

6.3.1 Functionality
The packet capturing tool is provided with the functionality to upload the sensor data to a MQTT Broker (ThingSpeak in this scenario). The packet values are uploaded to the cloud service and displayed under multiple graphs (one graph to display one packet type). The different packet types are assigned to variables by the following commands.  
# TaklBack Definition
# ThingsSpeak -> Apps -> TalkBack
TalkBackID = '15763'
TalkBackAPIKey = 'X0TF1DGNJFOY2G6W'
WKEY = '57U9CEIXT2WF00PC'
headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
The values are passed to the Cloud service using the commands
#Upload packet counter to ThingsSpeak
        params = urllib.parse.urlencode({"field1": broadcast_packet_total,"field2": dhcp_packet_total, "field3":dns_packet_total, "field4":arp_packet_total, "field5":icmp_packet_total, "field6":igmp_packet_total,"field7":syn_packet_total, "field8":http_packet_total,   "key": WKEY})
        conn = http.client.HTTPConnection("api.thingspeak.com:80")
        print( "=====Debug=======" )
        try:
            conn.request("POST", "/update", params, headers)
            response = conn.getresponse()
            print ("Status :", response.status,"Reason:", response.reason)
            data = response.read()
            conn.close()

The Cloud display graphs are updated frequently as the ‘upload data’ function is called within the ‘packet capturing’ loop. This enables the upload tool and packet capturing tool run simultaneously; increasing the accuracy of the published data. 
By analyzing the packet counter values, a network administrator can view the activity status of the network and helps to identify any abnormal network behavior. However, the management team has to define the threshold values for each packet type (the average number of packets transferred within the network in a given time) during peak hours; as this will trigger an alert if incorrectly configured. 

.  
Figure 6: Variable Assignment to MQTT Broker Web Dashboard





Critical Evaluation
The implemented application was tested for its functionality and multiple test procedures were utilized. ‘Cat Karat builder’ application was used to generate packets for application functionality testing. The test environment had certain limitations on the community-edition; only one type of packet generation allowed for a given instance and the application lacks functionality to generate HTTP traffic. Therefore each component was tested separately by generating their respective packet type.  
The Ethernet interface of the Raspberry Pi was changed to promiscuous mode. This enables the device to capture all the incoming packets without restriction. To enable promiscuous mode, the adapter parameters had to be changed; which disables the interface usage for other network-related purposes. Wireless adapter was configured for data publishing to the MQTT Broker. As Ethernet is preferred over wireless by default, the Ethernet connection is prioritized; disabling the wireless interface. Therefore, Wireless interface had to be manually prioritized over Ethernet connection. 
Raspbian Lite version is used over the default Raspbian Operating System as the application is resource intensive. LXAppearance theme is used to simplify the Graphical User Interface. As the key-point of the implementation is portability, the device power consumption plays a significant role. By using less-resource intensive Operating System, this challenge can be avoided. As the device doesn’t involve in displaying the data on a display while capturing packets, the Graphical User Interface is considered a negligible factor. But, a Graphical User Interface is used at the prototype for demonstration purposes. 
Considering the concept to check network-device activity, a separate Ethernet interface has to be used as the existing interface is dedicated for packet capturing.  This challenge can be easily overcome by using plug-in USB to Ethernet interfaces. The application efficiency and functionality can be increased by using the above method; where the network traffic can be monitored by multiple mirror-ports. 
