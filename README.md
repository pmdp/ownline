Ownline is a way to manage **remote** access to **private services** that run inside a home/office network (**LAN**).

Does this by using two forwarding techniques at different levels of the OSI model, ***"port forwarding"*** at the transport layer and ***"reverse proxy"*** at the application layer. By configuring the necessary rules with either of these two techniques, we gain access to a particular service within the LAN. Ownline abstracts these concepts and associates each of these "rules" to a user session, which is ephemeral and is linked to a public IP to allow access and a TCP/UDP port of the router to send requests to. In this way, we get temporary and IP-authenticated access to private services within our LAN from anywhere on the Internet.

Routing methods:

* **Port forwarding**: runs iptables rules directly on the router's firewall, the rule runs something like this: `iptables -t nat -I PREROUTING -s <trusted_ip>/32 -p tcp -m tcp --dport <port_dst> -j DNAT --to-destination <ip_dst>:<port_dst_lan>`\`
* **Web reverse proxy:** creates web services in nginx, which route (proxy) to other web services on the LAN. One advantage is to be able to use a single point of termination of the web encryption.

In addition, ownline also takes care of creating and updating sessions periodically in order to have constant and transparent access. It does this by obtaining the trusted IP of a user and sending it to ownline from time to time. Explained below in *"Automatic session update"*.

Ownline, is composed of 4 parts or modules (go to each repo for more info):

* **[ownline-core](https://github.com/pmdp/ownline-core)**: Creates the necessary rules to access LAN services, runs on the router, executes two services:
  * **SPA**: UDP server that waits for encrypted and authenticated messages from a public IP to allow access/sessions to services. These messages are redirected to ownline-web.
  * **CMD**: Server that receives commands via SSL sockets and is responsible for creating, deleting or modifying port forwarding or web proxy rules.
* **[ownline-web](https://github.com/pmdp/ownline-web)**: Flask web server that may or may not run on the router. It contains the logic and data of users, services, sessions, etc. This is where session creation actions are triggered. Does this by sending commands to ownline-core via SSL sockets where session creation and deletion messages are exchanged. Can also use MQTT and SPA to listen for automatic updates of users' public IPs. Requires a relational database. Also uses notification services such as system logs or telegram.
* **[ownline-pwa](https://github.com/pmdp/ownline-pwa):** Progressive web app to visuallize all services, create new sessions, access them, etc and also MQTT web client. Needs **ownline-web** as API backend. Runs as an offline app in the mobile or desktop.
* **[ownline-app](https://github.com/pmdp/ownline-app)**: Flutter android app. Runs at personal mobile device that wants automatic session creation. Sends messages periodically (\~15min) in background to your home router (SPA) or public server (MQTT).

## Automatic session update

The automatic session update is implemented in two different ways, which may or may not work at the same time:

* **SPA**: Single Packet Autentication. (*Recommended*) ownline-core runs a UDP server that waits for encrypted messages from trusted IPs, validates this message and forwards it to ownline-web to trigger an automatic session update for a user.
  * Disadvantages: needs an open UDP port on the router.
  * Advantages: no external server is required, the trusted IP is obtained from the IP header itself and not from the message.
* **MQTT**: ownline-web listens on an MQTT channel to receive public IP updates from a user.
  * Disadvantages: it needs a public server, the IP must be obtained at the client with third party services and sent in the message, so sometimes it may not match the real public IP that arrives at the home router and therefore not get access.
  * Advantages: no need to open an UDP port on the router.

### SPA flow diagram

![SPA flow diagram](resources/spa-flow-diagram.png)

### MQTT flow diagram

![MQTT flow diagram](resources/mqtt-flow-diagram.png)


### Screenshots
|   |   |
:-------------------------:|:-------------------------:
![Ownline PWA 1](resources/ownline_pwa_screenshot_1.png)  |  ![Ownline PWA 2](resources/ownline_pwa_screenshot_2.png)
![Ownline PWA 2](resources/ownline_pwa_screenshot_4.png)  |  ![Ownline PWA desktop](resources/ownline_pwa_screenshot_3.png)

![Ownline PWA desktop](resources/ownline-pwa-desktop.png)