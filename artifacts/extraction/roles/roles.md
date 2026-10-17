# Device-role inventory

Source interpretation and scope questions remain documented. Independent semantic review and current readiness are reported in the [plan audit](../validation/plan_audit/) and [current status](../validation/final_status.json).

[Explore the ontology hierarchy](ontology.md), [open the interactive visualization](ontology.html), or [download the OWL export](ontology.owl). Subtype edges and documented associations preserve distinct meanings and retain source evidence.

The inventory preserves generic categories, specialized roles, aggregate services, and management or realization facets. Repeated named instances are recorded separately in instances.json. Personnel roles are excluded in exclusions.json.

## ROLE-solution-component: Solution Component

Kind: device_or_service_role.

Generic component category to which the CP assigns solution-wide requirements. [Interpretation for review.]

Source wording: CSfC Solution Components, MSC Solution Components, SOLUTION COMPONENTS, Solution Component, Solution Components, solution components.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u018`

> 5 Solution Components.......................................................................................................................... 15

`CSFC-MSC-1.3.0-4e40e3d83708:p005:u023`

> 10.6 Port Filtering Solution Components Requirements .................................................................... 37

`CSFC-MSC-1.3.0-4e40e3d83708:p007:u007`

> Table 16. Port Filtering (PF) Solution Components Requirements ............................................................. 37

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u007.s001`

> Management plane traffic is used to configure and monitor Solution Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u007.s002`

> It includes the communications between a system administrator and a component, as well as the logs and other status information forwarded from a Solution Component to a SIEM, or similar repository.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s004`

> Since this device resides in the Gray Network, all requirements for Solution Components must be implemented.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s003`

> However, it is highly recommended to apply the general device management (DM) and port filtering requirements for Solution Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u003`

> 5 SOLUTION COMPONENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u005.s001`

> Each Solution Component is described in more detail below.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u008.s001`

> This CP includes design details for the provisioning and management of Solution Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s003`

> , the Red Network location) where MSC Solution Components are configured and initialized before their first use.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s001`

> Management traffic for all MSC Solution Components is always encrypted to protect confidentially and integrity, except in the case where components are locally managed through a direct physical connection (i.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s007`

> This requirement is not applicable if the MSC Solution Components are managed from the same LAN or VLAN.

`CSFC-MSC-1.3.0-4e40e3d83708:p031:u003.s002`

> CM also enables the detection of any configuration errors within Solution Components Continuous Monitoring (CM) Requirements have been relocated to a separate CSfC Continuous Monitoring Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p032:u012`

> PF Port Filtering Requirements for Solution Components Section 10.6 Table 16

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u008`

> MSC-PS-16 MSC Solution Components must be configured to use the NIAP-certified evaluated configuration. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u007`

> MSC-SR-5 Default accounts, passwords, community strings, and other default access control mechanisms for all Solution Components must be changed or removed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u005`

> MSC-SR-15 Solution Components must receive virus signature updates as required by the local agency policy and the AO. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u008`

> MSC-SR-18 Solution Components must only be configured over an interface dedicated for management. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u010`

> MSC-SR-20 DNS server addresses on Solution Components must be specified or DNS services must be disabled. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u011`

> MSC-SR-21 Automatic remote boot-time configuration services must be disabled on all solution components (i.e., automatic configuration via Trivial File Transfer Protocol on boot). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p037:u003`

> MSC-SR-24 All solution components (Firewalls, VPN Gateways, Authentication Servers, etc) must use software and firmware signing algorithms in Table 2. O Optional

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u010`

> 10.6 PORT FILTERING SOLUTION COMPONENTS REQUIREMENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u011.s001`

> Table 16 defines Port Filtering Solution Components Requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u012.s002`

> Port Filtering (PF) Solution Components Requirements

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u014`

> MSC-PF-1 All Solution Components must have all network interfaces restricted to the smallest address ranges, ports, and protocols possible. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u015`

> MSC-PF-2 All Solution Components must have all unused network interfaces disabled. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u003`

> MSC-DM-4 The Red Management Network must be used exclusively for all management of Inner Encryption Components and Solution Components within the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u004`

> MSC-DM-5 The Gray Network must be used exclusively for all management of the Outer Encryption Component, Gray Firewall, if present, and Solution Components within the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u006`

> MSC-DM-7 All components must be configured to restrict the IP address range for the network administration device to the smallest range possible. Note that locally managing Solution Components is also acceptable. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u007`

> MSC-DM-8 All administration of Solution Components must securely be performed from an AW remotely using an NSA-approved solution (e.g., CP or High Assurance encryptor), or by managing the Solution Components locally. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u008`

> MSC-DM-9 Security Administrators must authenticate to Solution Components before performing administrative functions. T MSC-DM-10

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u009`

> MSC-DM-10 Security Administrators must authenticate to Solution Components with CNSA Suite compliant certificates before performing administrative functions. O MSC-DM-9

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u011`

> MSC-DM-12 Authorized Security Administrators must initiate certificate signing requests for Solution Components as part of their initial keying within the solution. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p050:u013`

> MSC-GD-1 All Solution Components, with the exception of the Outer Firewall (if present), must be physically protected as classified devices, classified at the level of the network with the highest classification in the solution or in any other MSC Solutions with which it is interconnected. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p050:u014`

> MSC-GD-2 Only authorized and appropriately cleared (or escorted) administrators and security personnel must have physical access to the Solution Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p052:u005`

> MSC-GD-23 Local policy must dictate how the Security Administrator installs patches to Solution Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p052:u006`

> MSC-GD-24 Solution Components must comply with local TEMPEST policy. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p053:u005`

> MSC-RP-3 Solution Owners must report a security failure in any of the CSfC Solution Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p053:u009`

> MSC-RP-7 Solution Owners must report if a Solution Component sends traffic with an unauthorized destination address. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p053:u011`

> MSC-RP-9 Solution Owners must report any unauthorized escalation of privileges to any of the CSfC Solution Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p053:u013`

> MSC-RP-11 Solution Owners must report any evidence of malicious physical tampering with Solution Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p055:u016`

> MSC-RB-8 Security Administrators must initiate the certificate revocation/CAK destruction process prior to disposal of any Solution Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p056:u010.s001`

> • In case of a compromise, the AO ensures that certificate and CAK revocation information is updated on all the Solution Components in the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p059:u010.s001`

> Central Management Site – A site within a MSC Solution that is responsible for remotely managing the Solution Components located at other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u010.s001`

> Independently Managed Site – A site within a MSC Solution where Solution Components are locally managed and that does not remotely manage other sites’ Solution Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p061:u007.s001`

> Remote Site – A site within a MSC Solution where Solution Components are remotely managed by a Central Management Site.

## ROLE-encryption-component: Encryption Component

Kind: device_or_service_role.

Generic VPN Gateway or MACsec Device category. [Interpretation for review.]

Source wording: ENCRYPTION COMPONENT, ENCRYPTION COMPONENTS, Encryption Component, Encryption Components, encryption component.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u020`

> 5.2 Outer Encryption Component ..................................................................................................... 16

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u025`

> 5.5 Inner Encryption Components .................................................................................................... 18

`CSFC-MSC-1.3.0-4e40e3d83708:p005:u021`

> 10.4 Additional Inner Encryption Component Requirements ............................................................ 35

`CSFC-MSC-1.3.0-4e40e3d83708:p005:u022`

> 10.5 Additional Requirements for Outer Encryption Components .................................................... 36

`CSFC-MSC-1.3.0-4e40e3d83708:p006:u018`

> Figure 9. MSC Solution with Redundant Outer Encryption Components ................................................... 15

`CSFC-MSC-1.3.0-4e40e3d83708:p007:u005`

> Table 14. Additional Inner Encryption Component (IR) Requirements ...................................................... 35

`CSFC-MSC-1.3.0-4e40e3d83708:p007:u006`

> Table 15. Additional Outer Encryption Components (OR) Requirements .................................................. 36

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s001`

> Throughout this CP, the term “Encryption Component” refers generically to either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s002`

> “Inner Encryption Component” refers to the component that terminates the Inner layer of encryption and “Outer Encryption Component” refers to the component that terminates the Outer layer of encryption.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s001`

> As shown in Figure 1, before being sent across the untrusted network, each packet or frame of classified data is encrypted twice; first by an Inner Encryption Component, and then by an Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s002`

> At the other end of the data flow, the received packet is correspondingly decrypted twice; first by an Outer Encryption Component, and then by an Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label003`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label004`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label007`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s002`

> The Red Network is logically located behind an Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s006`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s007`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s001`

> Gray Network components consist of the Outer Encryption Component, Gray Firewall, and Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s006`

> As a result, neither Red nor Black AWs are permitted to manage the Outer Encryption Component, Gray Firewall, or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s007`

> Additionally, the Gray AWs are prohibited from managing Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u001.s002`

> Inner Encryption Components must be managed from a Red AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s002`

> The network connecting the Outer Encryption Components together is a Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s005`

> As shown in Figure 2, if the Black Network is an untrusted network such as the Public Internet, an Outer Firewall is required between the Black Network and the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label004`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label005`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label008`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label009`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s005`

> Restrictions are also placed on control plane traffic for the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s006`

> The Outer Encryption Component is prohibited from implementing routing protocols on external and internal interfaces.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s007`

> The Outer Encryption Component may not perform routing functionality.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u001.s002`

> Here, each Red Network has two Encryption Components associated with it; an Inner Encryption Component connected to the Red Network, and an Outer Encryption Component between the Inner Encryption Component and the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s001`

> There are two layers of encryption tunnels between any pair of sites communicating directly with one another; one encryption tunnel between their Outer Encryption Components, and a second encryption tunnel between their Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s002`

> Each set of Inner or Outer Encryption Components can provide encryption using either IPsec or MACsec.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label005`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label007`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label010`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label012`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s001`

> For independently managed sites, each site performs the administration of its own Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s003`

> Each site needs to ensure that the Encryption Components selected interoperate with those at the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s002`

> In the MSC Solution, Encryption Components at each site using public key certificates need to have the signing certificates and revocation information for the corresponding CAs used by the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label008`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label011`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label012`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s001`

> Because the central management site manages the Encryption Components at the other sites over the network, encryption is used to logically separate data and management traffic as it passes between sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s003`

> Red management traffic is encrypted before being routed through the Inner and Outer Encryption Components to another site.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s004`

> Although each Red Network requires its own Inner Encryption Component, a site may use a single Outer Encryption Component to encrypt and transport traffic that has been encrypted by Inner Encryption Components of varying security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s002`

> An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s008`

> Given both cases, separate CAs, CAKs, and management devices are needed to manage the Inner Encryption Components at each security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s009`

> For example, Figure 5 shows a Central Management Site (Site A) and a Remote Site (Site B), but network 1 and network 2 each has its own Red Management Services, which prevents the Inner Encryption Components of the two networks from being able to authenticate with one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s001`

> When Red Networks that operate at the same security level are implemented, the cryptographic separation provided by the Inner Encryption Components is sufficient to protect against unintended data flows between the two networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s002`

> Two Inner Encryption Components for networks of different security levels will be unable to mutually authenticate with each other because they trust different CAs that do not have a trust relationship with one another or they use different CAKs that will not provide authentication.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label009`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label011`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label015`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label017`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label018`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u005.s002`

> Any physical path through a Gray Network between multiple Inner Encryption Components supporting Red Networks of different security levels must include at least one filtering component.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s002`

> The IP address assigned must be unique to that security level such that each network’s Inner Encryption Component is only able to send and receive traffic to its respective Inner Encryption Component at the other site.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s001`

> Additionally, filtering components are included between the components used for management of the Gray Networks themselves (namely, AWs and locally run CAs) and Inner Encryption Components that support Red Networks of a lower security level than the Red Network with the highest security level supported by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s002`

> In other words, AWs and locally run CAs on Gray Networks are treated as, and grouped with, the Inner Encryption Component for the Red Network with the highest security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s002`

> Standalone Gray Firewalls have been placed at each site between the Inner Encryption Components and the Outer Encryption Component; these Gray Firewalls are responsible for dropping packets between Inner Encryption Components of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label009`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label012`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label014`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label018`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label021`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label024`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label026`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u004.s001`

> Figure 6 also shows an example placement of Gray Firewalls, as long as any path between Inner Encryption Components for networks of different security levels includes a Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s001`

> Including one or more standalone Gray Firewalls in a solution does not remove the requirement to perform the filtering on the Outer Encryption Component as well.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s002`

> Outer Encryption Components are uniquely positioned to block traffic between Inner Encryption Components supporting Red Networks of different security levels when one of those Inner Encryption Components is located at a different site.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003`

> If using a standalone device, the internal interface will be connected to the Inner MACsec Device and the external interface will be connected to the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:f07:label004`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p019:f07:label008`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p020:f08:label004`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p020:f08:label008`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s001`

> When the Inner Encryption Component is a MACsec Device the traffic requires additional encapsulation before it is passed through the Outer Encryption Component to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u006.s001`

> The MSC Solution provides mutual device authentication between Outer Encryption Components and between Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u004.s004`

> Multicast messages received on external interfaces of the Outer Encryption Component must be dropped.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s001`

> Figure 9 shows an MSC Solution between two sites where each site has a redundant Outer Encryption Component (Management components are omitted from the figure for clarity).

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s002`

> There are two outer encryption tunnels that transit the Black Network: one between the upper pair of Outer Encryption Components, and one between the lower pair of Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s005`

> The MSC Solution can maintain connectivity between the two sites even if one of the Outer Encryption Components fails because traffic will be routed through the tunnel that has not failed.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label008`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label009`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label010`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label013`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label015`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label016`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label017`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u001.s002`

> MSC Solution with Redundant Outer Encryption Components

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u002.s002`

> Implementing standby or failover Encryption Components, performing load balancing between Encryption Components, or other techniques to improve the availability or throughput of the solution are outside the scope of this CP and are not discussed further.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u003.s001`

> The external interface of the Outer Firewall only permits IPsec or MACsec traffic with a destination address of the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s001`

> The internal interface of the Outer Firewall only permits IPsec or MACsec traffic with a source address of the Outer Encryption Component and any necessary control plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u005.s001`

> As shown in Figure 2, the Outer Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u006`

> 5.2 OUTER ENCRYPTION COMPONENT

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s001`

> The Outer Encryption Component can be either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s002`

> The Outer Encryption Component establishes an encrypted tunnel using IPsec or MACsec with peer Outer Encryption Components, which provides device authentication, confidentiality, and integrity of information traversing Black Networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s001`

> If the Black Network is the Public Internet, the external interface of the Outer Encryption Component is connected to the internal interface of the Outer Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s002`

> Otherwise, the external interface of the Outer Encryption Component is connected to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s003`

> The internal interface of the Outer Encryption Component is connected to Gray Firewalls, if required, or Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s001`

> The Outer Encryption Component may be a perimeter device (if the Outer Firewall is not present) and more exposed to external attacks.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s002`

> The Outer Encryption Component may use internal filtering to help protect the network from unauthenticated traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s004`

> This CP does not require that the Outer Encryption Component terminate all tunnels on a single physical interface; however, all such external interfaces must conform to the port filtering requirements in Section 10.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s006`

> The Outer Encryption Component is implemented identically for all the high-level designs covered in this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s001`

> Outer Encryption Components are also responsible for filtering traffic on its Gray Network interfaces to prevent Inner Encryption Components for networks of the same security level from being able to send packets to one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002`

> Since this filtering is primarily based on the source and destination addresses in the packet on a Gray Network, the Gray Network itself must use an addressing scheme that supports the necessary filtering (such as using separate address ranges for the Gray interfaces of Inner Encryption Components supporting each Red Network).

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u011.s001`

> The Outer Encryption Component is prohibited from implementing routing protocols on external and internal interfaces and must rely on an Outer Firewall or Gray Firewall to provide dynamic routing functionality.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u001.s002`

> The Outer Encryption Component, selected from the CSfC Components List, must be physically separate from the Outer Firewall and Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u002.s001`

> The Outer Encryption Component cannot route packets between Gray and Black Networks; any packets received on a Gray Network interface and sent out on a Black Network interface must be transmitted within an IPsec or MACsec tunnel configured according to this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u003.s001`

> For load balancing or other performance reasons, multiple Outer Encryption Components that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s001`

> The Gray Firewall is located between the Outer Encryption Component and Inner Encryption Component(s).

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s006`

> The Gray Firewall blocks any packets sent between Inner Encryption Components for Red Networks of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s007`

> A Gray Firewall also blocks any packets sent between management components on the Gray Network and Inner Encryption Components for Red Networks that operate at a security level other than the highest security level of data protected by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s001`

> As shown in Figure 6, a standalone Gray Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component and Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s002`

> A Gray Firewall would typically only be used in solutions where the physical design of the Gray Network includes paths between Inner Encryption Components for Red Networks of different security levels that do not pass through the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s003`

> Effectively, each Gray Firewall is another instance of the Gray Network filtering performed by the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s002`

> The Gray AW is not permitted to maintain, monitor, or control Inner Encryption Components or Red Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s002`

> The SIEM is configured to provide alerts for specific events including if the Outer Encryption Component or Gray Firewall receives and drops any unexpected traffic that could indicate a compromise.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u002`

> 5.5 INNER ENCRYPTION COMPONENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s001`

> Inner Encryption Components can either be VPN Gateways or MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s002`

> For load balance or other performance reasons, multiple Inner Encryption Components that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u004.s001`

> Similar to an Outer Encryption Component, an Inner Encryption Component provides authentication of peer VPN Gateways or MACsec Devices, cryptographic protection of data in transit, and configuration and enforcement of network packet handling rules.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u005.s001`

> Similar to the Outer Encryption Component, the external interface of the Inner Encryption Component only permits egress of IPsec/MACsec traffic and AO-approved control plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u005.s002`

> The internal interface of the Inner Encryption Component is configured to only permit traffic with an IP address and port associated with Red Network services.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u006.s001`

> The Inner Encryption Component must not route packets between Red and Gray Networks; any packets received on a Red Network interface and sent to a Gray Network interface must be transmitted within an IPsec or MACsec tunnel configured according to this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u006.s002`

> The Inner Encryption Component, selected from the CSfC Components List, must be physically separate from the Gray Firewall and Inner Firewall, if either are required by this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s001`

> An Inner Firewall is located between the Inner Encryption Component and the Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u011.s001`

> Secure administration of Inner Encryption Components and continuous monitoring of the Red Network are essential roles provided by the Red Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s002`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002`

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s005`

> , Customer Edge Router), or could be added between Outer Encryption Components and existing Black Network components.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004`

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s003`

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u012.s001`

> For provisioning MACsec PSK Encryption Components, the Security Administrator obtains a Symmetric Key from an NSA-approved KGS and applies them to each Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s001`

> For provisioning Certificate-based MACsec, Outer Encryption Components and/or Inner Encryption Components generate a public/private key pair and output the public key in a CSR.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s002`

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u005.s001`

> Given the architecture of the solution, each layer has its own distinct administration LAN or VLAN; the Inner Encryption Component and supporting components are managed from the Red Management Services, and the Outer Encryption Component and supporting components are managed from the Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s001`

> The Gray AWs along with all Gray Management Services, are physically connected to the Gray Firewall, if required, or the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s003`

> , serial cable from a Gray AW to the Outer Encryption Component).

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s008`

> For example, a Gray AW residing within the Gray Management Services at the same site as the Outer Encryption Component need not use CNSA Suite algorithms since this traffic does not traverse an untrusted network.

`CSFC-MSC-1.3.0-4e40e3d83708:p032:u010`

> IR Additional Requirements for Inner Encryption Components Section 10.4 Table 14

`CSFC-MSC-1.3.0-4e40e3d83708:p032:u011`

> OR Additional Requirements for Outer Encryption Components Section 10.5 Table 15

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u010`

> MSC-PS-6 The Inner Encryption Component and the Outer Encryption Component must either; come from different manufacturers, where neither manufacturer is a subsidiary of the other; or be different products from the same manufacturer, where NSA has determined that the products meet the CSfC criteria for implementation independence. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u011`

> MSC-PS-7 The Inner Encryption Component and the Outer Encryption Component must not use the same Operating System. Differences between Service Packs and version numbers for a particular vendor's OS do not provide adequate diversity. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u012`

> MSC-PS-8 The cryptographic libraries used by the Inner Encryption Component and Outer Encryption Component must either; come from different manufacturers, where neither manufacturer is a subsidiary of the other; or be different libraries from the same manufacturer, where NSA has determined that the libraries meet the CSfC criteria for implementation independence. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u014`

> MSC-PS-10 If Gray Firewalls are used, the Gray Firewalls and Inner Encryption Components must either; come T=O from different manufacturers, where neither manufacturer is a subsidiary of the other; or be two different products from the same manufacturer, where NSA has determined that the two products meet the CSfC criteria for implementation independence.

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u003`

> MSC-PS-11 The Inner Encryption Component and Outer Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u004`

> MSC-PS-12 If an Outer Firewall and/or Gray Firewall is required, the Outer Firewall, Outer Encryption Component, Gray Firewall and Inner Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u003`

> MSC-SR-1 Network services provided by control plane protocols (such as NTP) must be located on the inside network (i.e., Gray Network for Outer Encryption Component and Red Network for Inner Encryption Component). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u004`

> MSC-SR-2 Sites that need to communicate must ensure that Encryption Components selected by each site for each tunnel are interoperable. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u005`

> MSC-SR-3 The time of day on the Inner Encryption Component and Red Management Services must be synchronized to a trusted time source located in the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u009`

> MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u012`

> MSC-SR-10 The Outer Encryption Component must use a unique physical internal interface for each Red Network in the MSC Solution (i.e., VLAN trunking of multiple enclaves is not permitted). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u002`

> MSC-SR-12 If the MSC Solution uses the Public Internet for its Black transport network, an Outer Firewall must be located between the Black transport network and the Outer Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u006`

> MSC-SR-16 When multiple Inner Encryption Components share an Outer Encryption Component, they must be placed in parallel. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u007`

> MSC-SR-17 Inner Encryption Components must not perform switching or routing for other Encryption Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u013`

> MSC-SR-23 The packet size for packets leaving the external interface of the Gray Firewall/Encryption Component must be configured to keep the packets T=O from being fragmented and impacting performance. This requires proper configuration of the Maximum Transmission Unit (MTU) for IPv4 or Path MTU (PMTU) for IPv6 and should consider the Outer VPN Gateway MTU/PMTU values for achievement.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u011`

> MSC-AA-2 The AS must only connect to one site’s network when a MACsec device is an Outer or Inner Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u014`

> 10.4 ADDITIONAL INNER ENCRYPTION COMPONENT REQUIREMENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u015.s001`

> Table 14 defines additional Inner Encryption Component Requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u016.s002`

> Additional Inner Encryption Component (IR) Requirements

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u019`

> MSC-IR-2 Packet sizes, or frames leaving the external interface of the Inner Encryption Component must be configured to reduce fragmentation and lessen the impact on performance. This requires proper O Optional configuration of the Maximum Transmission Unit (MTU) (for IPv4 or MACsec) or Path MTU (PMTU) (for IPv6) and should consider Black Network and Outer Encryption Component MTU/PMTU values to achieve this.

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u003`

> MSC-IR-3 The Inner Encryption Component must not allow packets received on an interface connected to a Red Network to bypass encryption and be forwarded out through an interface connected to a Gray Network. T MSC-IR-4

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u004`

> MSC-IR-4 The Inner Encryption Component must use a Mandatory Access Control policy to not allow packets received on an interface connected to a Red Network to bypass encryption and be forwarded out through an interface connected to a Gray Network. O MSC-IR-3

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u005`

> MSC-IR-5 The Inner Encryption Component must not allow packets received on an interface connected to a Gray Network to bypass decryption and be forwarded out through an interface connected to a Red Network. T MSC-IR-6

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u006`

> MSC-IR-6 The Inner Encryption Component must use Mandatory Access Control policy to not allow packets received on an interface connected to a Gray Network to bypass decryption and be forwarded out through an interface connected to a Red Network. O MSC-IR-5

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u007`

> MSC-IR-7 The Inner Encryption Component must not permit split-tunneling. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u008`

> 10.5 ADDITIONAL REQUIREMENTS FOR OUTER ENCRYPTION COMPONENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u009.s001`

> Table 15 defines additional Outer Encryption Components Requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s002`

> Additional Outer Encryption Components (OR) Requirements

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u013`

> MSC-OR-2 Outer Encryption Components must not allow packets received on an interface connected to a Gray Network to bypass encryption and be forwarded out through an interface connected to a Black Network. T MSC-OR-3

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u014`

> MSC-OR-3 Outer Encryption Components must use Mandatory Access Control policy to not allow packets received on an interface connected to a Gray Network to O MSC-OR-2 bypass encryption and be forwarded out through an interface connected to a Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u003`

> MSC-OR-4 All traffic received by Outer Encryption Components on an interface connected to a Gray Network, with the exception of control plane traffic, must have already been encrypted once. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u004`

> MSC-OR-5 Outer Encryption Components must not allow any packets received on an interface connected to a Black Network to bypass decryption. T MSC-OR-6

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u005`

> MSC-OR-6 Outer Encryption Components must use Mandatory Access Control policy to not allow any packets received on an interface connected to a Black Network to bypass decryption. O MSC-OR-5

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u006`

> MSC-OR-7 The Outer Encryption Components must not permit split-tunneling. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u007`

> MSC-OR-8 Outer Encryption Components must not use routing protocols (e.g., OSPF, BGP). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u009`

> MSC-OR-10 Packets leaving the external interface of the Outer Encryption Component must only make connections with the remote Outer Encryption Component or the other intended device. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u003`

> MSC-PF-5 For all Inner Encryption Component interfaces connected to a Gray Network, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, IPsec, MKA, MACsec, and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u004`

> MSC-PF-6 Any service or feature that allows an Outer Encryption Component to contact a third-party server (such as one maintained by the manufacturer) must be blocked. T MSC-PF-7

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u005`

> MSC-PF-7 Any service or feature that allows an Outer Encryption Component to contact a third party server (such as one maintained by the manufacturer) must be disabled. O MSC-PF-6

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u006`

> MSC-PF-8 Management plane traffic must only be initiated from a Gray AW with the exception of logging or authentication traffic that may be initiated from Outer Encryption Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u007`

> MSC-PF-9 Multicast messages received on external interfaces of Outer Encryption Components must be dropped. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u011`

> MSC-PF-13 The Gray Network interfaces of Outer Encryption Components must allow IKE and IPsec, or MKA and MACsec traffic, as appropriate, between two Inner Encryption Components protecting networks of the same security level or that is being used for management of the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u004`

> MSC-PF-17 The Gray Network interfaces of Outer Encryption Components must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u005`

> MSC-PF-18 The Gray Network interfaces of Outer Encryption Components must block all packets whose source address does not match a list of addresses or address ranges known to be reachable from the interface where the packet was received. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u006`

> MSC-PF-19 The Gray Network interfaces of Outer Encryption Components must allow management and control plane protocols (as defined in this CP) that have been approved by policy. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u007`

> MSC-PF-20 The Gray Network interfaces of Outer Encryption Components must deny all traffic that is not explicitly allowed by requirements MSC-PF-8, MSC- PF-13, MSC-PF-15, or MSC-PF-19. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u005`

> MSC-PF-28 If a Gray Firewall is required, the Gray Firewall must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u002`

> MSC-DM-3 AWs must connect from an internal port. Specifically, the Inner Encryption Component must be managed from the Red Network, and the Outer Encryption Component and Gray Firewall, if present, must be managed from the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u003`

> MSC-DM-4 The Red Management Network must be used exclusively for all management of Inner Encryption Components and Solution Components within the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u004`

> MSC-DM-5 The Gray Network must be used exclusively for all management of the Outer Encryption Component, Gray Firewall, if present, and Solution Components within the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u005`

> MSC-DM-17 The same AW must not be used to manage Inner Encryption Components and Outer Encryption Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u010`

> MSC-DM-22 Outer Encryption Components must only be managed by Security Administrators cleared to at least the highest level of classification of each Red Network supported by the Outer Encryption Component at the physical site the Outer Encryption Component is located. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p054:u003`

> MSC-RP-14 Solution Owners must report malicious discrepancies in the number of connections established by the Outer Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p054:u004`

> MSC-RP-15 Solution Owners must report malicious discrepancies in the number of connections established by the Inner Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p055:u013`

> MSC-RB-5 The Security Administrator(s) for the Inner Encryption Components and supporting components on the Red Network must be different individuals from the Security Administrator(s) for the Outer Encryption Components and supporting components on the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u004.s001`

> Encryption Component – Either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u005.s001`

> External Interface – The interface on an Encryption Component that connects to the outer network (i.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u005.s003`

> , the Gray Network on the Inner Encryption Component or the Black Network on the Outer Encryption Component).

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u012.s001`

> Internal Interface – The interface on an Encryption Component that connects to the inner network (i.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u012.s003`

> , the Gray Network on the Outer Encryption Component or the Red Network on the Inner Encryption Component).

## ROLE-inner-encryption: Inner Encryption Component

Kind: device_or_service_role.

Terminates the inner encryption layer. [Interpretation for review.]

Source wording: INNER ENCRYPTION COMPONENT, INNER ENCRYPTION COMPONENTS, Inner Encryption Component, Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u025`

> 5.5 Inner Encryption Components .................................................................................................... 18

`CSFC-MSC-1.3.0-4e40e3d83708:p005:u021`

> 10.4 Additional Inner Encryption Component Requirements ............................................................ 35

`CSFC-MSC-1.3.0-4e40e3d83708:p007:u005`

> Table 14. Additional Inner Encryption Component (IR) Requirements ...................................................... 35

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s002`

> “Inner Encryption Component” refers to the component that terminates the Inner layer of encryption and “Outer Encryption Component” refers to the component that terminates the Outer layer of encryption.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s001`

> As shown in Figure 1, before being sent across the untrusted network, each packet or frame of classified data is encrypted twice; first by an Inner Encryption Component, and then by an Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s002`

> At the other end of the data flow, the received packet is correspondingly decrypted twice; first by an Outer Encryption Component, and then by an Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label003`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s002`

> The Red Network is logically located behind an Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s006`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s007`

> Additionally, the Gray AWs are prohibited from managing Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u001.s002`

> Inner Encryption Components must be managed from a Red AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label004`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label008`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u001.s002`

> Here, each Red Network has two Encryption Components associated with it; an Inner Encryption Component connected to the Red Network, and an Outer Encryption Component between the Inner Encryption Component and the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s001`

> There are two layers of encryption tunnels between any pair of sites communicating directly with one another; one encryption tunnel between their Outer Encryption Components, and a second encryption tunnel between their Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label005`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label010`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label011`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s004`

> Although each Red Network requires its own Inner Encryption Component, a site may use a single Outer Encryption Component to encrypt and transport traffic that has been encrypted by Inner Encryption Components of varying security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s002`

> An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s008`

> Given both cases, separate CAs, CAKs, and management devices are needed to manage the Inner Encryption Components at each security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s009`

> For example, Figure 5 shows a Central Management Site (Site A) and a Remote Site (Site B), but network 1 and network 2 each has its own Red Management Services, which prevents the Inner Encryption Components of the two networks from being able to authenticate with one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s001`

> When Red Networks that operate at the same security level are implemented, the cryptographic separation provided by the Inner Encryption Components is sufficient to protect against unintended data flows between the two networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s002`

> Two Inner Encryption Components for networks of different security levels will be unable to mutually authenticate with each other because they trust different CAs that do not have a trust relationship with one another or they use different CAKs that will not provide authentication.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label009`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label015`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label017`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u005.s002`

> Any physical path through a Gray Network between multiple Inner Encryption Components supporting Red Networks of different security levels must include at least one filtering component.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s002`

> The IP address assigned must be unique to that security level such that each network’s Inner Encryption Component is only able to send and receive traffic to its respective Inner Encryption Component at the other site.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s001`

> Additionally, filtering components are included between the components used for management of the Gray Networks themselves (namely, AWs and locally run CAs) and Inner Encryption Components that support Red Networks of a lower security level than the Red Network with the highest security level supported by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s002`

> In other words, AWs and locally run CAs on Gray Networks are treated as, and grouped with, the Inner Encryption Component for the Red Network with the highest security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s002`

> Standalone Gray Firewalls have been placed at each site between the Inner Encryption Components and the Outer Encryption Component; these Gray Firewalls are responsible for dropping packets between Inner Encryption Components of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label009`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label012`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label018`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label021`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label024`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u004.s001`

> Figure 6 also shows an example placement of Gray Firewalls, as long as any path between Inner Encryption Components for networks of different security levels includes a Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s002`

> Outer Encryption Components are uniquely positioned to block traffic between Inner Encryption Components supporting Red Networks of different security levels when one of those Inner Encryption Components is located at a different site.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s001`

> When the Inner Encryption Component is a MACsec Device the traffic requires additional encapsulation before it is passed through the Outer Encryption Component to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u006.s001`

> The MSC Solution provides mutual device authentication between Outer Encryption Components and between Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label006`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label008`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label013`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label015`

> Inner Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s003`

> The internal interface of the Outer Encryption Component is connected to Gray Firewalls, if required, or Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s001`

> Outer Encryption Components are also responsible for filtering traffic on its Gray Network interfaces to prevent Inner Encryption Components for networks of the same security level from being able to send packets to one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002`

> Since this filtering is primarily based on the source and destination addresses in the packet on a Gray Network, the Gray Network itself must use an addressing scheme that supports the necessary filtering (such as using separate address ranges for the Gray interfaces of Inner Encryption Components supporting each Red Network).

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s001`

> The Gray Firewall is located between the Outer Encryption Component and Inner Encryption Component(s).

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s006`

> The Gray Firewall blocks any packets sent between Inner Encryption Components for Red Networks of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s007`

> A Gray Firewall also blocks any packets sent between management components on the Gray Network and Inner Encryption Components for Red Networks that operate at a security level other than the highest security level of data protected by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s001`

> As shown in Figure 6, a standalone Gray Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component and Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s002`

> A Gray Firewall would typically only be used in solutions where the physical design of the Gray Network includes paths between Inner Encryption Components for Red Networks of different security levels that do not pass through the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s002`

> The Gray AW is not permitted to maintain, monitor, or control Inner Encryption Components or Red Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u002`

> 5.5 INNER ENCRYPTION COMPONENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s001`

> Inner Encryption Components can either be VPN Gateways or MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s002`

> For load balance or other performance reasons, multiple Inner Encryption Components that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u004.s001`

> Similar to an Outer Encryption Component, an Inner Encryption Component provides authentication of peer VPN Gateways or MACsec Devices, cryptographic protection of data in transit, and configuration and enforcement of network packet handling rules.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u005.s001`

> Similar to the Outer Encryption Component, the external interface of the Inner Encryption Component only permits egress of IPsec/MACsec traffic and AO-approved control plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u005.s002`

> The internal interface of the Inner Encryption Component is configured to only permit traffic with an IP address and port associated with Red Network services.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u006.s001`

> The Inner Encryption Component must not route packets between Red and Gray Networks; any packets received on a Red Network interface and sent to a Gray Network interface must be transmitted within an IPsec or MACsec tunnel configured according to this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u006.s002`

> The Inner Encryption Component, selected from the CSfC Components List, must be physically separate from the Gray Firewall and Inner Firewall, if either are required by this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s001`

> An Inner Firewall is located between the Inner Encryption Component and the Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u011.s001`

> Secure administration of Inner Encryption Components and continuous monitoring of the Red Network are essential roles provided by the Red Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004`

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s001`

> For provisioning Certificate-based MACsec, Outer Encryption Components and/or Inner Encryption Components generate a public/private key pair and output the public key in a CSR.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u005.s001`

> Given the architecture of the solution, each layer has its own distinct administration LAN or VLAN; the Inner Encryption Component and supporting components are managed from the Red Management Services, and the Outer Encryption Component and supporting components are managed from the Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p032:u010`

> IR Additional Requirements for Inner Encryption Components Section 10.4 Table 14

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u010`

> MSC-PS-6 The Inner Encryption Component and the Outer Encryption Component must either; come from different manufacturers, where neither manufacturer is a subsidiary of the other; or be different products from the same manufacturer, where NSA has determined that the products meet the CSfC criteria for implementation independence. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u011`

> MSC-PS-7 The Inner Encryption Component and the Outer Encryption Component must not use the same Operating System. Differences between Service Packs and version numbers for a particular vendor's OS do not provide adequate diversity. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u012`

> MSC-PS-8 The cryptographic libraries used by the Inner Encryption Component and Outer Encryption Component must either; come from different manufacturers, where neither manufacturer is a subsidiary of the other; or be different libraries from the same manufacturer, where NSA has determined that the libraries meet the CSfC criteria for implementation independence. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u014`

> MSC-PS-10 If Gray Firewalls are used, the Gray Firewalls and Inner Encryption Components must either; come T=O from different manufacturers, where neither manufacturer is a subsidiary of the other; or be two different products from the same manufacturer, where NSA has determined that the two products meet the CSfC criteria for implementation independence.

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u003`

> MSC-PS-11 The Inner Encryption Component and Outer Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u004`

> MSC-PS-12 If an Outer Firewall and/or Gray Firewall is required, the Outer Firewall, Outer Encryption Component, Gray Firewall and Inner Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u003`

> MSC-SR-1 Network services provided by control plane protocols (such as NTP) must be located on the inside network (i.e., Gray Network for Outer Encryption Component and Red Network for Inner Encryption Component). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u005`

> MSC-SR-3 The time of day on the Inner Encryption Component and Red Management Services must be synchronized to a trusted time source located in the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u009`

> MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u006`

> MSC-SR-16 When multiple Inner Encryption Components share an Outer Encryption Component, they must be placed in parallel. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u007`

> MSC-SR-17 Inner Encryption Components must not perform switching or routing for other Encryption Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u011`

> MSC-AA-2 The AS must only connect to one site’s network when a MACsec device is an Outer or Inner Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u014`

> 10.4 ADDITIONAL INNER ENCRYPTION COMPONENT REQUIREMENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u015.s001`

> Table 14 defines additional Inner Encryption Component Requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u016.s002`

> Additional Inner Encryption Component (IR) Requirements

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u019`

> MSC-IR-2 Packet sizes, or frames leaving the external interface of the Inner Encryption Component must be configured to reduce fragmentation and lessen the impact on performance. This requires proper O Optional configuration of the Maximum Transmission Unit (MTU) (for IPv4 or MACsec) or Path MTU (PMTU) (for IPv6) and should consider Black Network and Outer Encryption Component MTU/PMTU values to achieve this.

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u003`

> MSC-IR-3 The Inner Encryption Component must not allow packets received on an interface connected to a Red Network to bypass encryption and be forwarded out through an interface connected to a Gray Network. T MSC-IR-4

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u004`

> MSC-IR-4 The Inner Encryption Component must use a Mandatory Access Control policy to not allow packets received on an interface connected to a Red Network to bypass encryption and be forwarded out through an interface connected to a Gray Network. O MSC-IR-3

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u005`

> MSC-IR-5 The Inner Encryption Component must not allow packets received on an interface connected to a Gray Network to bypass decryption and be forwarded out through an interface connected to a Red Network. T MSC-IR-6

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u006`

> MSC-IR-6 The Inner Encryption Component must use Mandatory Access Control policy to not allow packets received on an interface connected to a Gray Network to bypass decryption and be forwarded out through an interface connected to a Red Network. O MSC-IR-5

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u007`

> MSC-IR-7 The Inner Encryption Component must not permit split-tunneling. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u003`

> MSC-PF-5 For all Inner Encryption Component interfaces connected to a Gray Network, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, IPsec, MKA, MACsec, and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u011`

> MSC-PF-13 The Gray Network interfaces of Outer Encryption Components must allow IKE and IPsec, or MKA and MACsec traffic, as appropriate, between two Inner Encryption Components protecting networks of the same security level or that is being used for management of the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u004`

> MSC-PF-17 The Gray Network interfaces of Outer Encryption Components must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u005`

> MSC-PF-28 If a Gray Firewall is required, the Gray Firewall must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u002`

> MSC-DM-3 AWs must connect from an internal port. Specifically, the Inner Encryption Component must be managed from the Red Network, and the Outer Encryption Component and Gray Firewall, if present, must be managed from the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u003`

> MSC-DM-4 The Red Management Network must be used exclusively for all management of Inner Encryption Components and Solution Components within the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u005`

> MSC-DM-17 The same AW must not be used to manage Inner Encryption Components and Outer Encryption Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p054:u004`

> MSC-RP-15 Solution Owners must report malicious discrepancies in the number of connections established by the Inner Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p055:u013`

> MSC-RB-5 The Security Administrator(s) for the Inner Encryption Components and supporting components on the Red Network must be different individuals from the Security Administrator(s) for the Outer Encryption Components and supporting components on the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u005.s003`

> , the Gray Network on the Inner Encryption Component or the Black Network on the Outer Encryption Component).

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u012.s003`

> , the Gray Network on the Outer Encryption Component or the Red Network on the Inner Encryption Component).

## ROLE-outer-encryption: Outer Encryption Component

Kind: device_or_service_role.

Terminates the outer encryption layer. [Interpretation for review.]

Source wording: OUTER ENCRYPTION COMPONENT, OUTER ENCRYPTION COMPONENTS, Outer Encryption Component, Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u020`

> 5.2 Outer Encryption Component ..................................................................................................... 16

`CSFC-MSC-1.3.0-4e40e3d83708:p005:u022`

> 10.5 Additional Requirements for Outer Encryption Components .................................................... 36

`CSFC-MSC-1.3.0-4e40e3d83708:p006:u018`

> Figure 9. MSC Solution with Redundant Outer Encryption Components ................................................... 15

`CSFC-MSC-1.3.0-4e40e3d83708:p007:u006`

> Table 15. Additional Outer Encryption Components (OR) Requirements .................................................. 36

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s002`

> “Inner Encryption Component” refers to the component that terminates the Inner layer of encryption and “Outer Encryption Component” refers to the component that terminates the Outer layer of encryption.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s001`

> As shown in Figure 1, before being sent across the untrusted network, each packet or frame of classified data is encrypted twice; first by an Inner Encryption Component, and then by an Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s002`

> At the other end of the data flow, the received packet is correspondingly decrypted twice; first by an Outer Encryption Component, and then by an Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label004`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p010:f01:label007`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s007`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s001`

> Gray Network components consist of the Outer Encryption Component, Gray Firewall, and Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s006`

> As a result, neither Red nor Black AWs are permitted to manage the Outer Encryption Component, Gray Firewall, or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s002`

> The network connecting the Outer Encryption Components together is a Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s005`

> As shown in Figure 2, if the Black Network is an untrusted network such as the Public Internet, an Outer Firewall is required between the Black Network and the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label005`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label009`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s005`

> Restrictions are also placed on control plane traffic for the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s006`

> The Outer Encryption Component is prohibited from implementing routing protocols on external and internal interfaces.

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s007`

> The Outer Encryption Component may not perform routing functionality.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u001.s002`

> Here, each Red Network has two Encryption Components associated with it; an Inner Encryption Component connected to the Red Network, and an Outer Encryption Component between the Inner Encryption Component and the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s001`

> There are two layers of encryption tunnels between any pair of sites communicating directly with one another; one encryption tunnel between their Outer Encryption Components, and a second encryption tunnel between their Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u002.s002`

> Each set of Inner or Outer Encryption Components can provide encryption using either IPsec or MACsec.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label007`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label012`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label008`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label012`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s003`

> Red management traffic is encrypted before being routed through the Inner and Outer Encryption Components to another site.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u007.s004`

> Although each Red Network requires its own Inner Encryption Component, a site may use a single Outer Encryption Component to encrypt and transport traffic that has been encrypted by Inner Encryption Components of varying security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u001.s002`

> An unclassified network can also be included behind the Outer Encryption Component but must be behind its own Inner Encryption Component and meet the requirements in this CP as if it was a Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label011`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label018`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s002`

> Standalone Gray Firewalls have been placed at each site between the Inner Encryption Components and the Outer Encryption Component; these Gray Firewalls are responsible for dropping packets between Inner Encryption Components of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label014`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label026`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s001`

> Including one or more standalone Gray Firewalls in a solution does not remove the requirement to perform the filtering on the Outer Encryption Component as well.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s002`

> Outer Encryption Components are uniquely positioned to block traffic between Inner Encryption Components supporting Red Networks of different security levels when one of those Inner Encryption Components is located at a different site.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003`

> If using a standalone device, the internal interface will be connected to the Inner MACsec Device and the external interface will be connected to the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:f07:label004`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p019:f07:label008`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p020:f08:label004`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p020:f08:label008`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s001`

> When the Inner Encryption Component is a MACsec Device the traffic requires additional encapsulation before it is passed through the Outer Encryption Component to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u006.s001`

> The MSC Solution provides mutual device authentication between Outer Encryption Components and between Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u004.s004`

> Multicast messages received on external interfaces of the Outer Encryption Component must be dropped.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s001`

> Figure 9 shows an MSC Solution between two sites where each site has a redundant Outer Encryption Component (Management components are omitted from the figure for clarity).

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s002`

> There are two outer encryption tunnels that transit the Black Network: one between the upper pair of Outer Encryption Components, and one between the lower pair of Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s005`

> The MSC Solution can maintain connectivity between the two sites even if one of the Outer Encryption Components fails because traffic will be routed through the tunnel that has not failed.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label009`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label010`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label016`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label017`

> Outer Encryption Component

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u001.s002`

> MSC Solution with Redundant Outer Encryption Components

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u003.s001`

> The external interface of the Outer Firewall only permits IPsec or MACsec traffic with a destination address of the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s001`

> The internal interface of the Outer Firewall only permits IPsec or MACsec traffic with a source address of the Outer Encryption Component and any necessary control plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u005.s001`

> As shown in Figure 2, the Outer Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u006`

> 5.2 OUTER ENCRYPTION COMPONENT

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s001`

> The Outer Encryption Component can be either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s002`

> The Outer Encryption Component establishes an encrypted tunnel using IPsec or MACsec with peer Outer Encryption Components, which provides device authentication, confidentiality, and integrity of information traversing Black Networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s001`

> If the Black Network is the Public Internet, the external interface of the Outer Encryption Component is connected to the internal interface of the Outer Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s002`

> Otherwise, the external interface of the Outer Encryption Component is connected to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s003`

> The internal interface of the Outer Encryption Component is connected to Gray Firewalls, if required, or Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s001`

> The Outer Encryption Component may be a perimeter device (if the Outer Firewall is not present) and more exposed to external attacks.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s002`

> The Outer Encryption Component may use internal filtering to help protect the network from unauthenticated traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s004`

> This CP does not require that the Outer Encryption Component terminate all tunnels on a single physical interface; however, all such external interfaces must conform to the port filtering requirements in Section 10.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s006`

> The Outer Encryption Component is implemented identically for all the high-level designs covered in this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s001`

> Outer Encryption Components are also responsible for filtering traffic on its Gray Network interfaces to prevent Inner Encryption Components for networks of the same security level from being able to send packets to one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u011.s001`

> The Outer Encryption Component is prohibited from implementing routing protocols on external and internal interfaces and must rely on an Outer Firewall or Gray Firewall to provide dynamic routing functionality.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u001.s002`

> The Outer Encryption Component, selected from the CSfC Components List, must be physically separate from the Outer Firewall and Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u002.s001`

> The Outer Encryption Component cannot route packets between Gray and Black Networks; any packets received on a Gray Network interface and sent out on a Black Network interface must be transmitted within an IPsec or MACsec tunnel configured according to this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u003.s001`

> For load balancing or other performance reasons, multiple Outer Encryption Components that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s001`

> The Gray Firewall is located between the Outer Encryption Component and Inner Encryption Component(s).

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s001`

> As shown in Figure 6, a standalone Gray Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component and Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s002`

> A Gray Firewall would typically only be used in solutions where the physical design of the Gray Network includes paths between Inner Encryption Components for Red Networks of different security levels that do not pass through the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s003`

> Effectively, each Gray Firewall is another instance of the Gray Network filtering performed by the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s002`

> The SIEM is configured to provide alerts for specific events including if the Outer Encryption Component or Gray Firewall receives and drops any unexpected traffic that could indicate a compromise.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u004.s001`

> Similar to an Outer Encryption Component, an Inner Encryption Component provides authentication of peer VPN Gateways or MACsec Devices, cryptographic protection of data in transit, and configuration and enforcement of network packet handling rules.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u005.s001`

> Similar to the Outer Encryption Component, the external interface of the Inner Encryption Component only permits egress of IPsec/MACsec traffic and AO-approved control plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s002`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002`

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s005`

> , Customer Edge Router), or could be added between Outer Encryption Components and existing Black Network components.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004`

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s001`

> For provisioning Certificate-based MACsec, Outer Encryption Components and/or Inner Encryption Components generate a public/private key pair and output the public key in a CSR.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u005.s001`

> Given the architecture of the solution, each layer has its own distinct administration LAN or VLAN; the Inner Encryption Component and supporting components are managed from the Red Management Services, and the Outer Encryption Component and supporting components are managed from the Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s001`

> The Gray AWs along with all Gray Management Services, are physically connected to the Gray Firewall, if required, or the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s003`

> , serial cable from a Gray AW to the Outer Encryption Component).

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s008`

> For example, a Gray AW residing within the Gray Management Services at the same site as the Outer Encryption Component need not use CNSA Suite algorithms since this traffic does not traverse an untrusted network.

`CSFC-MSC-1.3.0-4e40e3d83708:p032:u011`

> OR Additional Requirements for Outer Encryption Components Section 10.5 Table 15

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u010`

> MSC-PS-6 The Inner Encryption Component and the Outer Encryption Component must either; come from different manufacturers, where neither manufacturer is a subsidiary of the other; or be different products from the same manufacturer, where NSA has determined that the products meet the CSfC criteria for implementation independence. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u011`

> MSC-PS-7 The Inner Encryption Component and the Outer Encryption Component must not use the same Operating System. Differences between Service Packs and version numbers for a particular vendor's OS do not provide adequate diversity. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u012`

> MSC-PS-8 The cryptographic libraries used by the Inner Encryption Component and Outer Encryption Component must either; come from different manufacturers, where neither manufacturer is a subsidiary of the other; or be different libraries from the same manufacturer, where NSA has determined that the libraries meet the CSfC criteria for implementation independence. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u003`

> MSC-PS-11 The Inner Encryption Component and Outer Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u004`

> MSC-PS-12 If an Outer Firewall and/or Gray Firewall is required, the Outer Firewall, Outer Encryption Component, Gray Firewall and Inner Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u003`

> MSC-SR-1 Network services provided by control plane protocols (such as NTP) must be located on the inside network (i.e., Gray Network for Outer Encryption Component and Red Network for Inner Encryption Component). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u012`

> MSC-SR-10 The Outer Encryption Component must use a unique physical internal interface for each Red Network in the MSC Solution (i.e., VLAN trunking of multiple enclaves is not permitted). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u002`

> MSC-SR-12 If the MSC Solution uses the Public Internet for its Black transport network, an Outer Firewall must be located between the Black transport network and the Outer Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u006`

> MSC-SR-16 When multiple Inner Encryption Components share an Outer Encryption Component, they must be placed in parallel. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u019`

> MSC-IR-2 Packet sizes, or frames leaving the external interface of the Inner Encryption Component must be configured to reduce fragmentation and lessen the impact on performance. This requires proper O Optional configuration of the Maximum Transmission Unit (MTU) (for IPv4 or MACsec) or Path MTU (PMTU) (for IPv6) and should consider Black Network and Outer Encryption Component MTU/PMTU values to achieve this.

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u008`

> 10.5 ADDITIONAL REQUIREMENTS FOR OUTER ENCRYPTION COMPONENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u009.s001`

> Table 15 defines additional Outer Encryption Components Requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u010.s002`

> Additional Outer Encryption Components (OR) Requirements

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u013`

> MSC-OR-2 Outer Encryption Components must not allow packets received on an interface connected to a Gray Network to bypass encryption and be forwarded out through an interface connected to a Black Network. T MSC-OR-3

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u014`

> MSC-OR-3 Outer Encryption Components must use Mandatory Access Control policy to not allow packets received on an interface connected to a Gray Network to O MSC-OR-2 bypass encryption and be forwarded out through an interface connected to a Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u003`

> MSC-OR-4 All traffic received by Outer Encryption Components on an interface connected to a Gray Network, with the exception of control plane traffic, must have already been encrypted once. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u004`

> MSC-OR-5 Outer Encryption Components must not allow any packets received on an interface connected to a Black Network to bypass decryption. T MSC-OR-6

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u005`

> MSC-OR-6 Outer Encryption Components must use Mandatory Access Control policy to not allow any packets received on an interface connected to a Black Network to bypass decryption. O MSC-OR-5

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u006`

> MSC-OR-7 The Outer Encryption Components must not permit split-tunneling. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u007`

> MSC-OR-8 Outer Encryption Components must not use routing protocols (e.g., OSPF, BGP). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u009`

> MSC-OR-10 Packets leaving the external interface of the Outer Encryption Component must only make connections with the remote Outer Encryption Component or the other intended device. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u004`

> MSC-PF-6 Any service or feature that allows an Outer Encryption Component to contact a third-party server (such as one maintained by the manufacturer) must be blocked. T MSC-PF-7

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u005`

> MSC-PF-7 Any service or feature that allows an Outer Encryption Component to contact a third party server (such as one maintained by the manufacturer) must be disabled. O MSC-PF-6

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u006`

> MSC-PF-8 Management plane traffic must only be initiated from a Gray AW with the exception of logging or authentication traffic that may be initiated from Outer Encryption Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u007`

> MSC-PF-9 Multicast messages received on external interfaces of Outer Encryption Components must be dropped. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u011`

> MSC-PF-13 The Gray Network interfaces of Outer Encryption Components must allow IKE and IPsec, or MKA and MACsec traffic, as appropriate, between two Inner Encryption Components protecting networks of the same security level or that is being used for management of the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u004`

> MSC-PF-17 The Gray Network interfaces of Outer Encryption Components must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u005`

> MSC-PF-18 The Gray Network interfaces of Outer Encryption Components must block all packets whose source address does not match a list of addresses or address ranges known to be reachable from the interface where the packet was received. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u006`

> MSC-PF-19 The Gray Network interfaces of Outer Encryption Components must allow management and control plane protocols (as defined in this CP) that have been approved by policy. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u007`

> MSC-PF-20 The Gray Network interfaces of Outer Encryption Components must deny all traffic that is not explicitly allowed by requirements MSC-PF-8, MSC- PF-13, MSC-PF-15, or MSC-PF-19. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u002`

> MSC-DM-3 AWs must connect from an internal port. Specifically, the Inner Encryption Component must be managed from the Red Network, and the Outer Encryption Component and Gray Firewall, if present, must be managed from the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u004`

> MSC-DM-5 The Gray Network must be used exclusively for all management of the Outer Encryption Component, Gray Firewall, if present, and Solution Components within the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u005`

> MSC-DM-17 The same AW must not be used to manage Inner Encryption Components and Outer Encryption Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u010`

> MSC-DM-22 Outer Encryption Components must only be managed by Security Administrators cleared to at least the highest level of classification of each Red Network supported by the Outer Encryption Component at the physical site the Outer Encryption Component is located. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p054:u003`

> MSC-RP-14 Solution Owners must report malicious discrepancies in the number of connections established by the Outer Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p055:u013`

> MSC-RB-5 The Security Administrator(s) for the Inner Encryption Components and supporting components on the Red Network must be different individuals from the Security Administrator(s) for the Outer Encryption Components and supporting components on the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u005.s003`

> , the Gray Network on the Inner Encryption Component or the Black Network on the Outer Encryption Component).

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u012.s003`

> , the Gray Network on the Outer Encryption Component or the Red Network on the Inner Encryption Component).

## ROLE-vpn-gateway: VPN Gateway

Kind: device_or_service_role.

Generates IPsec encryption tunnels. [Interpretation for review.]

Source wording: IPsec VPN Gateway, IPsec VPN Gateways, VPN Components, VPN GATEWAY, VPN Gateway, VPN Gateways.

`CSFC-MSC-1.3.0-4e40e3d83708:p005:u019`

> 10.2 VPN Gateway Requirements ....................................................................................................... 30

`CSFC-MSC-1.3.0-4e40e3d83708:p006:u028`

> Table 8. VPN Gateway (VG) Requirements ................................................................................................. 31

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s003`

> VPN Gateways and MACsec Devices are implemented as part of the network infrastructure.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s001`

> Throughout this CP, the term “Encryption Component” refers generically to either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s002`

> An IPsec tunnel is established between VPN Gateways.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u006.s002`

> The method of authentication is different for VPN Gateways and MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u007.s001`

> VPN Gateways authenticate via public key certificates.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u007.s002`

> VPN Gateways may also implement Internet Engineering Task Force (IETF) Request for Comments (RFC) 8784-compliant IKEv2 and use Pre-Shared Key (PSK) in addition to public key certificates to provide quantum resistant confidentiality.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s001`

> This CP requires all authentication certificates issued to VPN Gateways and MACsec Devices to be Non- Person Entity certificates.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s002`

> 2, all communications flowing across a Black Network are protected by at least two layers of encryption, implemented using IPsec tunnels generated by VPN Gateways or MACsec tunnels generated by MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s001`

> The Outer Encryption Component can be either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s001`

> Inner Encryption Components can either be VPN Gateways or MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u004.s001`

> Similar to an Outer Encryption Component, an Inner Encryption Component provides authentication of peer VPN Gateways or MACsec Devices, cryptographic protection of data in transit, and configuration and enforcement of network packet handling rules.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s002`

> Some VPN Gateways and MACsec Devices allow this encapsulation to occur on the incoming interface, prior to encrypting traffic for the outer tunnel.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u013.s002`

> 0 migration, the VPN Gateways will have to implement CNSA 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:f10:label001`

> IPsec VPN Gateway “Bob”

`CSFC-MSC-1.3.0-4e40e3d83708:p028:f10:label002`

> IPsec VPN Gateway “Alice”

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s001`

> For provisioning IPsec Outer VPN Gateways and Inner VPN Gateways generate a public/private key pair and output the public key in a Certificate Signing Request (CSR).

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s002`

> The Security Administrator delivers the Outer Encryption’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p032:u007`

> VG VPN Gateway Requirements Section 10.2 Table 8

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u005`

> MSC-PS-1 The products used for any VPN Gateway must be chosen from the list of IPsec VPN Gateways on the CSfC Components List. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u013`

> MSC-SR-23 The packet size for packets leaving the external interface of the Gray Firewall/Encryption Component must be configured to keep the packets T=O from being fragmented and impacting performance. This requires proper configuration of the Maximum Transmission Unit (MTU) for IPv4 or Path MTU (PMTU) for IPv6 and should consider the Outer VPN Gateway MTU/PMTU values for achievement.

`CSFC-MSC-1.3.0-4e40e3d83708:p037:u003`

> MSC-SR-24 All solution components (Firewalls, VPN Gateways, Authentication Servers, etc) must use software and firmware signing algorithms in Table 2. O Optional

`CSFC-MSC-1.3.0-4e40e3d83708:p037:u004`

> 10.2 VPN GATEWAY REQUIREMENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p037:u005.s001`

> This section addresses requirements for VPN Gateways.

`CSFC-MSC-1.3.0-4e40e3d83708:p037:u005.s006`

> Table 8 defines requirements for VPN Gateways.

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u004.s002`

> VPN Gateway (VG) Requirements

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u006`

> MSC-VG-1 The proposals offered by VPN Gateways in the course of establishing the Internet Key Exchange (IKE) Security Association and the Encapsulating Security Payload (ESP) SA for inner and outer tunnels must be configured to offer algorithm suite(s) containing only CNSA 1.0 algorithms as detailed in Table 6. T MSC-VG-19, MSC-VG-20, and MSC-VG- 21

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u007`

> MSC-VG-2 Default, self-signed or proprietary device certificates, which are frequently preinstalled by the vendor, for any VPN Gateway must not be used for establishing SAs. T MSC-VG-3

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u008`

> MSC-VG-3 Default, self-signed or proprietary device certificates, which are frequently preinstalled by the vendor, for any VPN Gateway must be removed. O MSC-VG-2

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u009`

> MSC-VG-4 When using certificate-based authentication, a unique device certificate must be loaded onto each VPN Gateway along with the corresponding CA certificate chain, to include the Trust Anchor CA certificate. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u010`

> MSC-VG-5 The private key stored on VPN Gateways must not be accessible through an interface. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u011`

> MSC-VG-6 A device certificate must be used for VPN Gateway authentication during IKE. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u012`

> MSC-VG-7 VPN Gateway authentication must include a check that the certificate is not revoked, which can include a CRL, OCSP Responder, or other similar revocation reporting mechanism. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u013`

> MSC-VG-8 The VPN Gateway authentication must include a check that certificates are not expired. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u014`

> MSC-VG-9 All VPN Gateways must use IKEv2 (IETF RFC 7296) key exchange. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u002`

> MSC-VG-10 All VPN Gateways must use Cipher Block Chaining for IKE encryption. T MSC-VG-18

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u003`

> MSC-VG-11 All VPN Gateways must use Cipher Block Chaining for ESP encryption with a Host-based Message Authentication Code for integrity. T MSC-VG-12

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u004`

> MSC-VG-12 All VPN Gateways must use Galois Counter Mode for ESP encryption. O MSC-VG-11

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u005`

> MSC-VG-13 All VPN Gateways must set the IKE SA lifetime to at most 24 hours. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u006`

> MSC-VG-14 All VPN Gateways must set the ESP SA lifetime to no more than 8 hours. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u007`

> MSC-VG-15 Inner VPN Gateways must only authenticate and establish an IPsec tunnel with one another if their Red Networks operate at the same security level as defined in this CP. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u008`

> MSC-VG-16 All VPN Gateways must re-authenticate the identity of the VPN Gateway at the other end of the established tunnel before rekeying the IKE SA. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u009`

> MSC-VG-17 The Mandatory Access Control policy must only allow the VPN Gateway to access the private key of the VPN Gateway. O Optional

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u010`

> MSC-VG-18 All VPN Gateways must use Galois Counter Mode (GCM) for IKE encryption. O MSC-VG-10

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u013`

> MSC-VG-21 The VPN Components must use algorithms from the algorithm suite in Table 7 for all IPsec VPN O MSC-VG-1 tunnels, with the exception of the IKE_SA_INIT exchange.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u018`

> MSC-IR-1 The Inner VPN Gateway must use ESP Tunnel mode IPsec, with an associated IP tunneling protocol. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u012`

> MSC-OR-1 Outer VPN Gateways must use ESP Tunnel mode IPsec. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u016`

> MSC-PF-3 For all Outer VPN Gateway interfaces connected to a Black Network, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u008`

> MSC-PF-10 For solutions using IPv4, Outer VPN Gateways using IPsec must drop all packets that use IP options. O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u009`

> MSC-PF-11 For solutions using IPv4, each VPN Gateway must only accept packets with Transmission Control Protocol (TCP), User Datagram Protocol (UDP), ESP, or ICMP in the IPv4 Protocol field and drop all other packets. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u010`

> MSC-PF-12 For solutions using IPv6, each VPN Gateway must only accept packets with ESP, TCP, UDP, or ICMPv6 in the IPv6 Next Header field and drop all other packets. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u013`

> MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u012`

> MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u009`

> MSC-PF-32 The Gray Firewall must block all traffic routed to and between two or more Inner VPN Gateways of different classification levels. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u002`

> MSC-DM-14 AWs that interact with the Certificate Authority for the Outer VPN Gateways must be located on the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u001.s001`

> CRL Distribution Point (CDP) – A web server that hosts a copy of a CRL issued by a CA for VPN Gateways to download (see CSfC Key Management Requirements Annex).

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u004.s001`

> Encryption Component – Either a VPN Gateway or a MACsec Device.

## ROLE-inner-vpn: Inner VPN Gateway

Kind: device_or_service_role.

VPN Gateway serving the inner encryption layer. [Interpretation for review.]

Source wording: Inner VPN Gateway, Inner VPN Gateways.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s001`

> For provisioning IPsec Outer VPN Gateways and Inner VPN Gateways generate a public/private key pair and output the public key in a Certificate Signing Request (CSR).

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s002`

> The Security Administrator delivers the Outer Encryption’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p039:u007`

> MSC-VG-15 Inner VPN Gateways must only authenticate and establish an IPsec tunnel with one another if their Red Networks operate at the same security level as defined in this CP. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u018`

> MSC-IR-1 The Inner VPN Gateway must use ESP Tunnel mode IPsec, with an associated IP tunneling protocol. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u013`

> MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u012`

> MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u009`

> MSC-PF-32 The Gray Firewall must block all traffic routed to and between two or more Inner VPN Gateways of different classification levels. T=O

## ROLE-outer-vpn: Outer VPN Gateway

Kind: device_or_service_role.

VPN Gateway serving the outer encryption layer. [Interpretation for review.]

Source wording: Outer VPN Gateway, Outer VPN Gateways.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s001`

> For provisioning IPsec Outer VPN Gateways and Inner VPN Gateways generate a public/private key pair and output the public key in a Certificate Signing Request (CSR).

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u013`

> MSC-SR-23 The packet size for packets leaving the external interface of the Gray Firewall/Encryption Component must be configured to keep the packets T=O from being fragmented and impacting performance. This requires proper configuration of the Maximum Transmission Unit (MTU) for IPv4 or Path MTU (PMTU) for IPv6 and should consider the Outer VPN Gateway MTU/PMTU values for achievement.

`CSFC-MSC-1.3.0-4e40e3d83708:p043:u012`

> MSC-OR-1 Outer VPN Gateways must use ESP Tunnel mode IPsec. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u016`

> MSC-PF-3 For all Outer VPN Gateway interfaces connected to a Black Network, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u008`

> MSC-PF-10 For solutions using IPv4, Outer VPN Gateways using IPsec must drop all packets that use IP options. O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u013`

> MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u002`

> MSC-DM-14 AWs that interact with the Certificate Authority for the Outer VPN Gateways must be located on the Gray Network. T=O

## ROLE-macsec-device: MACsec Device

Kind: device_or_service_role.

Generates MACsec encryption tunnels. [Interpretation for review.]

Source wording: MACSEC DEVICE, MACsec Device, MACsec Devices, MACsec Ethernet Encryptors, MACsec device.

`CSFC-MSC-1.3.0-4e40e3d83708:p005:u020`

> 10.3 MACsec Device Requirements .................................................................................................... 33

`CSFC-MSC-1.3.0-4e40e3d83708:p007:u003`

> Table 12. MACsec Device (MD) Requirements ........................................................................................... 34

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s002`

> The two encryption tunnels protecting a data flow can use either Internet Protocol Security (IPsec) generated by a Virtual Private Network (VPN) Gateway or Media Access Control Security (MACsec) generated by a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u005.s003`

> VPN Gateways and MACsec Devices are implemented as part of the network infrastructure.

`CSFC-MSC-1.3.0-4e40e3d83708:p010:u006.s001`

> Throughout this CP, the term “Encryption Component” refers generically to either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s004`

> Similarly, MACsec Devices using a Connectivity Association Key (CAK) need to have the same CAK used by the other site in the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s005`

> If MACsec Devices are authenticating using certificates, the authentication server (AS) must not connect to both Gray and/or Red Networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u007.s003`

> A MACsec tunnel is established between MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s001`

> The MACsec-encrypted traffic needs to be encapsulated if the MACsec Device is the first layer of encryption in the MSC Solution or if the MACsec-encrypted traffic needs to traverse an IP-based network.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s001`

> In some commercial MACsec Devices, encapsulation can be applied on the internal interface by creating a pseudowire (see Figure 7), which emulates a point-to-point connection.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003`

> If using a standalone device, the internal interface will be connected to the Inner MACsec Device and the external interface will be connected to the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:f07:label003`

> MACsec Device

`CSFC-MSC-1.3.0-4e40e3d83708:p019:f07:label007`

> MACsec Device

`CSFC-MSC-1.3.0-4e40e3d83708:p020:f08:label003`

> MACsec Device

`CSFC-MSC-1.3.0-4e40e3d83708:p020:f08:label007`

> MACsec Device

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s001`

> When the Inner Encryption Component is a MACsec Device the traffic requires additional encapsulation before it is passed through the Outer Encryption Component to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u003.s007`

> If supported in the MACsec Device, this CP allows VLAN ID tags to be used in the clear.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u004.s001`

> At high speeds (100 GB/s or higher), some MACsec Devices may be configured to use an extended Packet Number (XPN), as described in IEEE 802.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u004.s004`

> If supported in the MACsec Device, this CP allows the XPN feature to be used.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u006.s002`

> The method of authentication is different for VPN Gateways and MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s001`

> MACsec Devices authenticate using a PSK called a CAK or using EAP-TLS over 802.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s005`

> The Key Server authenticates the other MACsec Device and issues a Secure Association Key to provide confidentiality and integrity for the MACsec tunnel.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s001`

> This CP requires all authentication certificates issued to VPN Gateways and MACsec Devices to be Non- Person Entity certificates.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s002`

> 2, all communications flowing across a Black Network are protected by at least two layers of encryption, implemented using IPsec tunnels generated by VPN Gateways or MACsec tunnels generated by MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u007.s001`

> The Outer Encryption Component can be either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u003.s001`

> Inner Encryption Components can either be VPN Gateways or MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u004.s001`

> Similar to an Outer Encryption Component, an Inner Encryption Component provides authentication of peer VPN Gateways or MACsec Devices, cryptographic protection of data in transit, and configuration and enforcement of network packet handling rules.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s002`

> Some VPN Gateways and MACsec Devices allow this encapsulation to occur on the incoming interface, prior to encrypting traffic for the outer tunnel.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s001`

> The MSC AS is responsible for mutual authentication between MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s002`

> Authentication must be established between the MACsec device and the AS, where each MACsec device must perform the functions of a supplicant and authenticator.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s003`

> This communication is used throughout the EAP-TLS negotiation to mutually authenticate two MACsec Devices to pass MACsec traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s005`

> 0-compliant algorithms as part of the EAP-TLS negotiation to mutually authenticate the MACsec Devices with ML-KEM 1024 for key establishment and ML-DSA 87 for digital signatures as vendors enable support for these algorithms.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s002`

> 0 migration, MACsec Devices will have to implement CNSA 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p028:u004.s005`

> The EAP-TLS negotiation to mutually authenticate MACsec Devices will need to use ML-KEM 1024 for key establishment and ML-DSA 87 for digital signatures.

`CSFC-MSC-1.3.0-4e40e3d83708:p032:u008`

> MD MACsec Device Requirements Section 10.3 Table 12

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u006`

> MSC-PS-2 The products used for any MACsec Device must be chosen from the list of MACsec Ethernet Encryptors on the CSfC Components List. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p040:u003`

> 10.3 MACSEC DEVICE REQUIREMENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p040:u004.s001`

> This section addresses requirements for MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p040:u004.s007`

> Table 12 defines MACsec Device requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u004.s002`

> MACsec Device (MD) Requirements

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u006`

> MSC-MD-1 MACsec Devices must use AES Key Wrap for key distribution with a cryptographic key size of 256 bits. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u007`

> MSC-MD-2 MACsec Devices must use AES GCM for MACsec with a cryptographic key size of 256 bits. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u008`

> MSC-MD-3 MACsec Devices must authenticate using Pre-Shared Keys (PSKs), known as Connectivity Association Keys (CAKs). T MSC-MD-14

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u010`

> MSC-MD-5 MACsec Devices must have the length of the CKN set to a minimum of 16 bytes (128 bits) and generate the CKN using an NSA-approved KGS. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u011`

> MSC-MD-6 For each pair of MACsec Devices establishing an encryption tunnel, one of the two must be configured to be the Key Server by setting its Key Server value to 0 (zero). The other MACsec Device must have its Key Server value set to 1. If a Central Management Site is part of the MSC Solution, it must be the Key Server. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u012`

> MSC-MD-7 MACsec Devices must enable data delay protection for MACsec Key Agreement (MKA). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u013`

> MSC-MD-8 MACsec Devices must have an MKA Lifetime Timeout limit set to 6.0 seconds and Hello Timeout limit set to 2.0 seconds. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u014`

> MSC-MD-9 MACsec Devices must have the replay window set to 2 or as low as possible given the nature of the Black Network being traversed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u015`

> MSC-MD-10 MACsec Devices must require all data traffic on an external facing port to be encrypted (e.g., must- secure). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u016`

> MSC-MD-11 MACsec Device configuration files, whether printed or electronically copied, must be physically T=O protected to the highest classification of the MACsec Device's CAK.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u003`

> MSC-MD-12 MACsec Devices must have the Confidentiality Offset set to 0 (zero). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u005`

> MSC-MD-14 MACsec Devices must authenticate using EAP-TLS (certificate based). T MSC-MD-3

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u007`

> MSC-MD-16 MACsec Devices must be configured to “must- secure”. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u010`

> MSC-AA-1 The AS must be used to provide mutual authentication using EAP-TLS with device certificates between MACsec Devices. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u011`

> MSC-AA-2 The AS must only connect to one site’s network when a MACsec device is an Outer or Inner Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u012`

> MSC-AA-3 The MACsec Devices and the AS must use the CNSA 1.0 EAP-TLS Ciphersuite in Table 10. T MSC-AA-4

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u013`

> MSC-AA-4 The MACsec Devices and the AS must use the CNSA 2.0 EAP-TLS Ciphersuite in Table 11. O MSC-AA-3

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u017`

> MSC-PF-4 For all Outer MACsec Device interfaces connected to a Black Network, traffic filtering rules must be T=O applied to both inbound and outbound traffic, such that only MACsec Protocol Data Units and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u004.s001`

> Encryption Component – Either a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u013.s001`

> Key Server – The MACsec Device designated as the one responsible for distribution Secure Association Keys to the other MACsec Device.

## ROLE-inner-macsec: Inner MACsec Device

Kind: device_or_service_role.

MACsec Device serving the inner encryption layer. [Interpretation for review.]

Source wording: Inner MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003`

> If using a standalone device, the internal interface will be connected to the Inner MACsec Device and the external interface will be connected to the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001`

> When an Inner MACsec Device is used, the MACsec traffic needs to be encapsulated prior to being processed by the Outer Encryption Component, regardless of whether it is a VPN Gateway or a MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

## ROLE-outer-macsec: Outer MACsec Device

Kind: device_or_service_role.

MACsec Device serving the outer encryption layer. [Interpretation for review.]

Source wording: Outer MACsec Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u017`

> MSC-PF-4 For all Outer MACsec Device interfaces connected to a Black Network, traffic filtering rules must be T=O applied to both inbound and outbound traffic, such that only MACsec Protocol Data Units and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed.

## ROLE-firewall: Firewall

Kind: device_or_service_role.

Traffic filtering component category. [Interpretation for review.]

Source wording: FIREWALL, Firewall, Firewalls, Traffic Filtering Firewalls, firewall, traffic filtering firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u019`

> 5.1 Outer Firewall ............................................................................................................................. 16

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u021`

> 5.3 Gray Firewall ............................................................................................................................... 17

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u026`

> 5.6 Inner Firewall .............................................................................................................................. 18

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s006`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s001`

> Gray Network components consist of the Outer Encryption Component, Gray Firewall, and Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s003`

> Gray Management Services are physically connected to the Gray Firewall and include, at a minimum, a AW that can be a physical workstation or Virtual Machine (VM).

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s006`

> As a result, neither Red nor Black AWs are permitted to manage the Outer Encryption Component, Gray Firewall, or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s005`

> As shown in Figure 2, if the Black Network is an untrusted network such as the Public Internet, an Outer Firewall is required between the Black Network and the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label006`

> Outer Firewall

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label010`

> Outer Firewall

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s008`

> If an Outer Firewall is present, the Outer Firewall can perform routing functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s001`

> When multiple security levels are used, it is critical to enforce proper IP address assignment and firewall rule sets.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s001`

> One or more Gray Firewalls must be included in the Gray Network to perform filtering.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s002`

> Standalone Gray Firewalls have been placed at each site between the Inner Encryption Components and the Outer Encryption Component; these Gray Firewalls are responsible for dropping packets between Inner Encryption Components of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label015`

> Gray Firewall

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label027`

> Gray Firewall

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u004.s001`

> Figure 6 also shows an example placement of Gray Firewalls, as long as any path between Inner Encryption Components for networks of different security levels includes a Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s001`

> Including one or more standalone Gray Firewalls in a solution does not remove the requirement to perform the filtering on the Outer Encryption Component as well.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u006.s002`

> The only exception to this requirement would be the Outer Firewall if one is present in the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u001`

> 5.1 OUTER FIREWALL

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s001`

> An MSC Solution that uses an untrusted network such as the Public Internet as its Black Network must include an Outer Firewall (see Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s004`

> The Outer Firewall is located at the edge of the MSC Solution and is connected to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u003.s001`

> The external interface of the Outer Firewall only permits IPsec or MACsec traffic with a destination address of the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s001`

> The internal interface of the Outer Firewall only permits IPsec or MACsec traffic with a source address of the Outer Encryption Component and any necessary control plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s002`

> The minimum requirements for port filtering on the Outer Firewall can be found in Section 10.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u005.s001`

> As shown in Figure 2, the Outer Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s001`

> If the Black Network is the Public Internet, the external interface of the Outer Encryption Component is connected to the internal interface of the Outer Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s003`

> The internal interface of the Outer Encryption Component is connected to Gray Firewalls, if required, or Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s001`

> The Outer Encryption Component may be a perimeter device (if the Outer Firewall is not present) and more exposed to external attacks.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u011.s001`

> The Outer Encryption Component is prohibited from implementing routing protocols on external and internal interfaces and must rely on an Outer Firewall or Gray Firewall to provide dynamic routing functionality.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u001.s002`

> The Outer Encryption Component, selected from the CSfC Components List, must be physically separate from the Outer Firewall and Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u004`

> 5.3 GRAY FIREWALL

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s001`

> The Gray Firewall is located between the Outer Encryption Component and Inner Encryption Component(s).

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s005`

> 2, an MSC Solution that supports multiple Red Networks of different security levels must include one or more Gray Firewalls.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s006`

> The Gray Firewall blocks any packets sent between Inner Encryption Components for Red Networks of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s007`

> A Gray Firewall also blocks any packets sent between management components on the Gray Network and Inner Encryption Components for Red Networks that operate at a security level other than the highest security level of data protected by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s008`

> Gray Firewalls are physically protected as classified devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s001`

> As shown in Figure 6, a standalone Gray Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component and Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s002`

> A Gray Firewall would typically only be used in solutions where the physical design of the Gray Network includes paths between Inner Encryption Components for Red Networks of different security levels that do not pass through the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s003`

> Effectively, each Gray Firewall is another instance of the Gray Network filtering performed by the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s004`

> For load balancing or other performance reasons, multiple Gray Firewalls that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s002`

> The SIEM is configured to provide alerts for specific events including if the Outer Encryption Component or Gray Firewall receives and drops any unexpected traffic that could indicate a compromise.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u006.s002`

> The Inner Encryption Component, selected from the CSfC Components List, must be physically separate from the Gray Firewall and Inner Firewall, if either are required by this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u008`

> 5.6 INNER FIREWALL

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s001`

> An Inner Firewall is located between the Inner Encryption Component and the Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s002`

> In this CP, an Inner Firewall is not required.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s003`

> If the MSC Solution is deployed with solutions from other CSfC CPs then those CPs will specify the Inner Firewall requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004`

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s001`

> The Gray AWs along with all Gray Management Services, are physically connected to the Gray Firewall, if required, or the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s002`

> The Gray Firewall maintains separate Access Control Lists (ACLs) to permit management traffic to/from the Gray Management Services but prohibits such traffic from all other components.

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u007`

> MSC-PS-3 The products used for any Firewalls must be chosen from the list of Traffic Filtering Firewalls on the CSfC Components List. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u014`

> MSC-PS-10 If Gray Firewalls are used, the Gray Firewalls and Inner Encryption Components must either; come T=O from different manufacturers, where neither manufacturer is a subsidiary of the other; or be two different products from the same manufacturer, where NSA has determined that the two products meet the CSfC criteria for implementation independence.

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u004`

> MSC-PS-12 If an Outer Firewall and/or Gray Firewall is required, the Outer Firewall, Outer Encryption Component, Gray Firewall and Inner Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u009`

> MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u013`

> MSC-SR-11 A Gray Firewall must be implemented if the MSC Solution is combined with another CSfC solution that requires a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u002`

> MSC-SR-12 If the MSC Solution uses the Public Internet for its Black transport network, an Outer Firewall must be located between the Black transport network and the Outer Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u003`

> MSC-SR-13 If the MSC Solution is combined with other CSfC data-in-transit solutions that include end user devices, the Inner Firewall requirements from that CP must be followed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u013`

> MSC-SR-23 The packet size for packets leaving the external interface of the Gray Firewall/Encryption Component must be configured to keep the packets T=O from being fragmented and impacting performance. This requires proper configuration of the Maximum Transmission Unit (MTU) for IPv4 or Path MTU (PMTU) for IPv6 and should consider the Outer VPN Gateway MTU/PMTU values for achievement.

`CSFC-MSC-1.3.0-4e40e3d83708:p037:u003`

> MSC-SR-24 All solution components (Firewalls, VPN Gateways, Authentication Servers, etc) must use software and firmware signing algorithms in Table 2. O Optional

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u008`

> MSC-OR-9 Outer Encryption must enable TRANSEC when external interface is MACsec enabled and connected to the Outer Firewall. O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u009`

> MSC-PF-22 If an Outer Firewall is required, for all Outer Firewall interfaces, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, MKA, MACsec and control plane protocols (as defined in this CP) approved by organization- defined policy are allowed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u010`

> MSC-PF-23 If a Gray Firewall is required (i.e., networks of multiple protection levels are included in the solution) the Gray Firewall must allow appropriate traffic (IKE, IPsec, MKA and MACsec) between Red Networks operating at the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u012`

> MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u004`

> MSC-PF-27 If a Gray Firewall is required, the Gray Firewall must only accept management traffic on the physical ports connected to the Gray Management Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u005`

> MSC-PF-28 If a Gray Firewall is required, the Gray Firewall must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u006`

> MSC-PF-29 If a Gray Firewall is required, the Gray Firewall must block all packets whose source address does not match a list of addresses or address ranges known to be reachable from the interface where the packet was received. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u007`

> MSC-PF-30 If a Gray Firewall is required, the Gray Firewall must allow control plane traffic (e.g., NTP and DHCP). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u008`

> MSC-PF-31 If a Gray Firewall is required, the Gray Firewall must deny all traffic that is not explicitly allowed by requirements MSC-PF-23, MSC-PF-25, MSC-PF-27 or MSC-PF-30. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u009`

> MSC-PF-32 The Gray Firewall must block all traffic routed to and between two or more Inner VPN Gateways of different classification levels. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u002`

> MSC-DM-3 AWs must connect from an internal port. Specifically, the Inner Encryption Component must be managed from the Red Network, and the Outer Encryption Component and Gray Firewall, if present, must be managed from the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u004`

> MSC-DM-5 The Gray Network must be used exclusively for all management of the Outer Encryption Component, Gray Firewall, if present, and Solution Components within the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u013`

> MSC-DM-25 The Gray Management and Gray Data Networks must be at minimum logically separated by the Gray Firewall using ACL. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p050:u013`

> MSC-GD-1 All Solution Components, with the exception of the Outer Firewall (if present), must be physically protected as classified devices, classified at the level of the network with the highest classification in the solution or in any other MSC Solutions with which it is interconnected. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u009.s001`

> Gray Firewall – A traffic filtering firewall placed on the Gray Network to provide additional separation between flows of singly-encrypted data of different security levels.

## ROLE-outer-firewall: Outer Firewall

Kind: device_or_service_role.

Filters traffic between the Black Network and Outer Encryption Component. [Interpretation for review.]

Source wording: OUTER FIREWALL, Outer Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u019`

> 5.1 Outer Firewall ............................................................................................................................. 16

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u003.s005`

> As shown in Figure 2, if the Black Network is an untrusted network such as the Public Internet, an Outer Firewall is required between the Black Network and the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label006`

> Outer Firewall

`CSFC-MSC-1.3.0-4e40e3d83708:p012:f02:label010`

> Outer Firewall

`CSFC-MSC-1.3.0-4e40e3d83708:p013:u006.s008`

> If an Outer Firewall is present, the Outer Firewall can perform routing functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u006.s002`

> The only exception to this requirement would be the Outer Firewall if one is present in the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u001`

> 5.1 OUTER FIREWALL

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s001`

> An MSC Solution that uses an untrusted network such as the Public Internet as its Black Network must include an Outer Firewall (see Section 4.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u002.s004`

> The Outer Firewall is located at the edge of the MSC Solution and is connected to the Black Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u003.s001`

> The external interface of the Outer Firewall only permits IPsec or MACsec traffic with a destination address of the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s001`

> The internal interface of the Outer Firewall only permits IPsec or MACsec traffic with a source address of the Outer Encryption Component and any necessary control plane traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u004.s002`

> The minimum requirements for port filtering on the Outer Firewall can be found in Section 10.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u005.s001`

> As shown in Figure 2, the Outer Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s001`

> If the Black Network is the Public Internet, the external interface of the Outer Encryption Component is connected to the internal interface of the Outer Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s001`

> The Outer Encryption Component may be a perimeter device (if the Outer Firewall is not present) and more exposed to external attacks.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u011.s001`

> The Outer Encryption Component is prohibited from implementing routing protocols on external and internal interfaces and must rely on an Outer Firewall or Gray Firewall to provide dynamic routing functionality.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u001.s002`

> The Outer Encryption Component, selected from the CSfC Components List, must be physically separate from the Outer Firewall and Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004`

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u004`

> MSC-PS-12 If an Outer Firewall and/or Gray Firewall is required, the Outer Firewall, Outer Encryption Component, Gray Firewall and Inner Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u002`

> MSC-SR-12 If the MSC Solution uses the Public Internet for its Black transport network, an Outer Firewall must be located between the Black transport network and the Outer Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p044:u008`

> MSC-OR-9 Outer Encryption must enable TRANSEC when external interface is MACsec enabled and connected to the Outer Firewall. O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u009`

> MSC-PF-22 If an Outer Firewall is required, for all Outer Firewall interfaces, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, MKA, MACsec and control plane protocols (as defined in this CP) approved by organization- defined policy are allowed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p050:u013`

> MSC-GD-1 All Solution Components, with the exception of the Outer Firewall (if present), must be physically protected as classified devices, classified at the level of the network with the highest classification in the solution or in any other MSC Solutions with which it is interconnected. T=O

## ROLE-gray-firewall: Gray Firewall

Kind: device_or_service_role.

Filters Gray Network traffic between encryption components and management components. [Interpretation for review.]

Source wording: GRAY FIREWALL, Gray Firewall, Gray Firewalls.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u021`

> 5.3 Gray Firewall ............................................................................................................................... 17

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s001`

> Gray Network components consist of the Outer Encryption Component, Gray Firewall, and Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s003`

> Gray Management Services are physically connected to the Gray Firewall and include, at a minimum, a AW that can be a physical workstation or Virtual Machine (VM).

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s006`

> As a result, neither Red nor Black AWs are permitted to manage the Outer Encryption Component, Gray Firewall, or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s001`

> One or more Gray Firewalls must be included in the Gray Network to perform filtering.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u002.s002`

> Standalone Gray Firewalls have been placed at each site between the Inner Encryption Components and the Outer Encryption Component; these Gray Firewalls are responsible for dropping packets between Inner Encryption Components of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label015`

> Gray Firewall

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label027`

> Gray Firewall

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u004.s001`

> Figure 6 also shows an example placement of Gray Firewalls, as long as any path between Inner Encryption Components for networks of different security levels includes a Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u005.s001`

> Including one or more standalone Gray Firewalls in a solution does not remove the requirement to perform the filtering on the Outer Encryption Component as well.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u008.s003`

> The internal interface of the Outer Encryption Component is connected to Gray Firewalls, if required, or Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u011.s001`

> The Outer Encryption Component is prohibited from implementing routing protocols on external and internal interfaces and must rely on an Outer Firewall or Gray Firewall to provide dynamic routing functionality.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u001.s002`

> The Outer Encryption Component, selected from the CSfC Components List, must be physically separate from the Outer Firewall and Gray Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u004`

> 5.3 GRAY FIREWALL

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s001`

> The Gray Firewall is located between the Outer Encryption Component and Inner Encryption Component(s).

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s005`

> 2, an MSC Solution that supports multiple Red Networks of different security levels must include one or more Gray Firewalls.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s006`

> The Gray Firewall blocks any packets sent between Inner Encryption Components for Red Networks of different security levels.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s007`

> A Gray Firewall also blocks any packets sent between management components on the Gray Network and Inner Encryption Components for Red Networks that operate at a security level other than the highest security level of data protected by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s008`

> Gray Firewalls are physically protected as classified devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s001`

> As shown in Figure 6, a standalone Gray Firewall, selected from the CSfC Components List, must be physically separate from the Outer Encryption Component and Inner Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s002`

> A Gray Firewall would typically only be used in solutions where the physical design of the Gray Network includes paths between Inner Encryption Components for Red Networks of different security levels that do not pass through the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s003`

> Effectively, each Gray Firewall is another instance of the Gray Network filtering performed by the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u006.s004`

> For load balancing or other performance reasons, multiple Gray Firewalls that comply with the requirements of this CP are acceptable.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s002`

> The SIEM is configured to provide alerts for specific events including if the Outer Encryption Component or Gray Firewall receives and drops any unexpected traffic that could indicate a compromise.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u006.s002`

> The Inner Encryption Component, selected from the CSfC Components List, must be physically separate from the Gray Firewall and Inner Firewall, if either are required by this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004`

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s001`

> The Gray AWs along with all Gray Management Services, are physically connected to the Gray Firewall, if required, or the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s002`

> The Gray Firewall maintains separate Access Control Lists (ACLs) to permit management traffic to/from the Gray Management Services but prohibits such traffic from all other components.

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u014`

> MSC-PS-10 If Gray Firewalls are used, the Gray Firewalls and Inner Encryption Components must either; come T=O from different manufacturers, where neither manufacturer is a subsidiary of the other; or be two different products from the same manufacturer, where NSA has determined that the two products meet the CSfC criteria for implementation independence.

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u004`

> MSC-PS-12 If an Outer Firewall and/or Gray Firewall is required, the Outer Firewall, Outer Encryption Component, Gray Firewall and Inner Encryption Component must use physically separate components, such that no component is used for more than one function. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u009`

> MSC-SR-7 All physical paths within a Gray Network between Inner Encryption Components for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u013`

> MSC-SR-11 A Gray Firewall must be implemented if the MSC Solution is combined with another CSfC solution that requires a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u013`

> MSC-SR-23 The packet size for packets leaving the external interface of the Gray Firewall/Encryption Component must be configured to keep the packets T=O from being fragmented and impacting performance. This requires proper configuration of the Maximum Transmission Unit (MTU) for IPv4 or Path MTU (PMTU) for IPv6 and should consider the Outer VPN Gateway MTU/PMTU values for achievement.

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u010`

> MSC-PF-23 If a Gray Firewall is required (i.e., networks of multiple protection levels are included in the solution) the Gray Firewall must allow appropriate traffic (IKE, IPsec, MKA and MACsec) between Red Networks operating at the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u012`

> MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u004`

> MSC-PF-27 If a Gray Firewall is required, the Gray Firewall must only accept management traffic on the physical ports connected to the Gray Management Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u005`

> MSC-PF-28 If a Gray Firewall is required, the Gray Firewall must only permit packets whose source and destination IP addresses match the external interfaces of Inner Encryption Components that support Red Networks of the same security level. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u006`

> MSC-PF-29 If a Gray Firewall is required, the Gray Firewall must block all packets whose source address does not match a list of addresses or address ranges known to be reachable from the interface where the packet was received. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u007`

> MSC-PF-30 If a Gray Firewall is required, the Gray Firewall must allow control plane traffic (e.g., NTP and DHCP). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u008`

> MSC-PF-31 If a Gray Firewall is required, the Gray Firewall must deny all traffic that is not explicitly allowed by requirements MSC-PF-23, MSC-PF-25, MSC-PF-27 or MSC-PF-30. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u009`

> MSC-PF-32 The Gray Firewall must block all traffic routed to and between two or more Inner VPN Gateways of different classification levels. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u002`

> MSC-DM-3 AWs must connect from an internal port. Specifically, the Inner Encryption Component must be managed from the Red Network, and the Outer Encryption Component and Gray Firewall, if present, must be managed from the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u004`

> MSC-DM-5 The Gray Network must be used exclusively for all management of the Outer Encryption Component, Gray Firewall, if present, and Solution Components within the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u013`

> MSC-DM-25 The Gray Management and Gray Data Networks must be at minimum logically separated by the Gray Firewall using ACL. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u009.s001`

> Gray Firewall – A traffic filtering firewall placed on the Gray Network to provide additional separation between flows of singly-encrypted data of different security levels.

## ROLE-inner-firewall: Inner Firewall

Kind: device_or_service_role.

Located between the Inner Encryption Component and Red Network; requirements may come from another CP. [Interpretation for review.]

Source wording: INNER FIREWALL, Inner Firewall.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u026`

> 5.6 Inner Firewall .............................................................................................................................. 18

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s006`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u006.s002`

> The Inner Encryption Component, selected from the CSfC Components List, must be physically separate from the Gray Firewall and Inner Firewall, if either are required by this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u008`

> 5.6 INNER FIREWALL

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s001`

> An Inner Firewall is located between the Inner Encryption Component and the Red Network.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s002`

> In this CP, an Inner Firewall is not required.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u009.s003`

> If the MSC Solution is deployed with solutions from other CSfC CPs then those CPs will specify the Inner Firewall requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004`

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u003`

> MSC-SR-13 If the MSC Solution is combined with other CSfC data-in-transit solutions that include end user devices, the Inner Firewall requirements from that CP must be followed. T=O

## ROLE-aw: Administrative Workstation

Kind: device_or_service_role.

Maintains, monitors, and controls component security functions; may be physical or virtual. [Interpretation for review.]

Source wording: ADMINISTRATIVE WORKSTATION, AW, AWs, Administrative Workstation, MW, Management Workstation.

`CSFC-MSC-1.3.0-4e40e3d83708:p002:u003`

> Commercial Solutions for Classified (CSfC) Multi-Site Connectivity (MSC) Capability Package (CP) 1.3.0 27 March 2026 • Added new CNSA 2.0 objective requirements: MSC-SR-24, MSC-VG-19, MSC-VG-20, and MSC-AA-4. • Added new Approved CNSA 2.0 Algorithms Tables 2, 7, and 11. • Updated Section 2 to include CNSS Policy 15 algorithms. • Added Section 5.11 -- CNSA 2.0 IPsec. • Provided language clarification in section 5.1 and 4.1.3 regarding Public Internet. • Updated MSC-GD-10, MSC-GD-11, MSC- GD-15, MSC-SR-21 language to add more clarity. • Changed Management Workstation to Administrative Workstation. • Updated MSC-PS-8, MSC-PS-14, MSC- DM-20, MSC-DM-21 to remove “Optional”. • Updated Table 7 and included SHA-512. • Various formatting and document cleanup.

`CSFC-MSC-1.3.0-4e40e3d83708:p003:u002`

> CSfC MSC Capability Package 1.2.0 2 March 2023 • Clarified Logging. • Expanded Management Workstation Options. • Improved Community of Interest Separation Requirements. • Eliminated Transport Mode IPsec as an Alternate to Tunnel Mode IPsec. • Clarified Filtering Requirements. • Added Objective Requirements for Transmission Security (TRANSEC). • Updated the CP to fully use the MKA feature set (Objective Requirements). • Ensured clarification across the entire CP and supporting documents. • Minor administrative changes made in editing and formatting.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u023`

> 5.4.1 Gray Administrative Workstation (AW) .............................................................................. 17

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s005`

> Red Networks are under the control of the Solution Owner or a trusted third party using a Red Administrative Workstation (AW).

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s006`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s007`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s003`

> Gray Management Services are physically connected to the Gray Firewall and include, at a minimum, a AW that can be a physical workstation or Virtual Machine (VM).

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s005`

> This CP requires the management of Gray Network components through a Gray AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s006`

> As a result, neither Red nor Black AWs are permitted to manage the Outer Encryption Component, Gray Firewall, or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s007`

> Additionally, the Gray AWs are prohibited from managing Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u001.s002`

> Inner Encryption Components must be managed from a Red AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s001`

> Additionally, filtering components are included between the components used for management of the Gray Networks themselves (namely, AWs and locally run CAs) and Inner Encryption Components that support Red Networks of a lower security level than the Red Network with the highest security level supported by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s002`

> In other words, AWs and locally run CAs on Gray Networks are treated as, and grouped with, the Inner Encryption Component for the Red Network with the highest security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u002.s002`

> As described in this CP, Management traffic on a Gray Network, which originates from the AW, must include two layers of encryption.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u009`

> 5.4.1 GRAY ADMINISTRATIVE WORKSTATION (AW)

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s002`

> The Gray AW is not permitted to maintain, monitor, or control Inner Encryption Components or Red Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s003`

> All MSC Solutions must have at least one Gray AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s002`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s003`

> All MSC Solutions will have at least one Red AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s001`

> Each component in the solution has one or more AWs that maintain, monitor, and control all security functions for that component.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s002`

> It should be noted that all of the required administrative functionality does not need to be present in each individual management component, but the entire set of AWs must collectively meet administrative functionality requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s001`

> AWs may be virtual machines (VMs) on a physical host/server that is dedicated to hosting AWs VMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s003`

> A physical host/server that hosts AWs VMs may not host VMs used for non-CSfC purposes.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s005`

> AWs (physical or virtual) must be configured, patched, and operated in accordance to the organizational or local policy.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s006`

> AWs must also be powered off when not in use.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s001`

> The Gray AWs along with all Gray Management Services, are physically connected to the Gray Firewall, if required, or the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s003`

> , serial cable from a Gray AW to the Outer Encryption Component).

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s008`

> For example, a Gray AW residing within the Gray Management Services at the same site as the Outer Encryption Component need not use CNSA Suite algorithms since this traffic does not traverse an untrusted network.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u006`

> MSC-PF-8 Management plane traffic must only be initiated from a Gray AW with the exception of logging or authentication traffic that may be initiated from Outer Encryption Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u016`

> MSC-DM-1 If using physical AWs, they must be dedicated for the purposes given in this CP and must be physically separated from workstations used to manage non-CSfC solutions. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u017`

> MSC-DM-2 AWs (or hosts/servers hosting VMs serving as AWs) must physically reside within a protected facility where CSfC solution(s) are managed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u002`

> MSC-DM-3 AWs must connect from an internal port. Specifically, the Inner Encryption Component must be managed from the Red Network, and the Outer Encryption Component and Gray Firewall, if present, must be managed from the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u007`

> MSC-DM-8 All administration of Solution Components must securely be performed from an AW remotely using an NSA-approved solution (e.g., CP or High Assurance encryptor), or by managing the Solution Components locally. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u002`

> MSC-DM-14 AWs that interact with the Certificate Authority for the Outer VPN Gateways must be located on the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u005`

> MSC-DM-17 The same AW must not be used to manage Inner Encryption Components and Outer Encryption Components. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u014`

> MSC-DM-26 AWs (physical or virtual) must be configured, patched, and operated in accordance with applicable Operating System vendor hardening guide and the organizational or local policy. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u015`

> MSC-DM-27 AWs (physical or virtual) must be powered off when not in use. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u016`

> MSC-DM-28 The AW must not also be used for provisioning, certificate registrations, and SIEM services. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u017`

> MSC-DM-29 Each AW admin must have a unique login credential. Group accounts are prohibited. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u014.s001`

> Locally Managed Device – A device that is being managed by the direct connection of the AW to the device in a hardwired fashion (such as a console cable).

`CSFC-MSC-1.3.0-4e40e3d83708:p062:u008`

> AW Administrative Workstation

`CSFC-MSC-1.3.0-4e40e3d83708:p063:u010`

> MW Management Workstation

## ROLE-red-aw: Red Administrative Workstation

Kind: device_or_service_role.

Administers Inner Encryption Components, Inner Firewall, and Red Management Services. [Interpretation for review.]

Source wording: Red AW, Red AWs, Red Administrative Workstation.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s005`

> Red Networks are under the control of the Solution Owner or a trusted third party using a Red Administrative Workstation (AW).

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s006`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s007`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u001.s002`

> Inner Encryption Components must be managed from a Red AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s002`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s003`

> All MSC Solutions will have at least one Red AW.

## ROLE-gray-aw: Gray Administrative Workstation

Kind: device_or_service_role.

Administers Outer Encryption Components, Gray Firewall, and Gray Management Services. [Interpretation for review.]

Source wording: GRAY ADMINISTRATIVE WORKSTATION, Gray AW, Gray AWs, Gray Administrative Workstation.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u023`

> 5.4.1 Gray Administrative Workstation (AW) .............................................................................. 17

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s005`

> This CP requires the management of Gray Network components through a Gray AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s007`

> Additionally, the Gray AWs are prohibited from managing Inner Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u009`

> 5.4.1 GRAY ADMINISTRATIVE WORKSTATION (AW)

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s002`

> The Gray AW is not permitted to maintain, monitor, or control Inner Encryption Components or Red Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s003`

> All MSC Solutions must have at least one Gray AW.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s001`

> The Gray AWs along with all Gray Management Services, are physically connected to the Gray Firewall, if required, or the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s003`

> , serial cable from a Gray AW to the Outer Encryption Component).

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s008`

> For example, a Gray AW residing within the Gray Management Services at the same site as the Outer Encryption Component need not use CNSA Suite algorithms since this traffic does not traverse an untrusted network.

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u006`

> MSC-PF-8 Management plane traffic must only be initiated from a Gray AW with the exception of logging or authentication traffic that may be initiated from Outer Encryption Components. T=O

## ROLE-black-aw: Black Administrative Workstation

Kind: device_or_service_role.

Mentioned to prohibit Black AW management of Gray components; no positive MSC assignment is supplied. [Interpretation for review.]

Source wording: Black AWs.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s006`

> As a result, neither Red nor Black AWs are permitted to manage the Outer Encryption Component, Gray Firewall, or Gray Management Services.

## ROLE-management-component: Management component

Kind: aggregate_component_service_role.

Generic component providing management functions; exact realization depends on the stated role. [Interpretation for review.]

Source wording: MANAGEMENT COMPONENTS, Management Components, Management Service Components, Management Service components, Management components, administration components, management component, management components, management devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u028`

> 5.7.1 Red Administration Management Components ................................................................. 19

`CSFC-MSC-1.3.0-4e40e3d83708:p005:u002`

> 5.9 Key and Certificate Management Components .......................................................................... 19

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s006`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s008`

> Given both cases, separate CAs, CAKs, and management devices are needed to manage the Inner Encryption Components at each security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s001`

> Figure 9 shows an MSC Solution between two sites where each site has a redundant Outer Encryption Component (Management components are omitted from the figure for clarity).

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u005.s007`

> A Gray Firewall also blocks any packets sent between management components on the Gray Network and Inner Encryption Components for Red Networks that operate at a security level other than the highest security level of data protected by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u001`

> 5.7.1 RED ADMINISTRATION MANAGEMENT COMPONENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u007`

> 5.9 KEY AND CERTIFICATE MANAGEMENT COMPONENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s002`

> It should be noted that all of the required administrative functionality does not need to be present in each individual management component, but the entire set of AWs must collectively meet administrative functionality requirements.

`CSFC-MSC-1.3.0-4e40e3d83708:p054:u013.s002`

> The Auditor will only be authorized access to Outer and Inner administration components.

## ROLE-red-management: Red Management Services

Kind: aggregate_component_service_role.

Aggregate services for secure inner-layer administration and Red Network monitoring. [Interpretation for review.]

Source wording: RED ADMINISTRATION MANAGEMENT COMPONENTS, RED MANAGEMENT SERVICES, Red Administration Management Components, Red Management Service, Red Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u027`

> 5.7 Red Management Services.......................................................................................................... 18

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u028`

> 5.7.1 Red Administration Management Components ................................................................. 19

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s006`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label006`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label011`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label007`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s009`

> For example, Figure 5 shows a Central Management Site (Site A) and a Remote Site (Site B), but network 1 and network 2 each has its own Red Management Services, which prevents the Inner Encryption Components of the two networks from being able to authenticate with one another.

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label007`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label010`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label007`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label010`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label013`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label019`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label022`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label025`

> Red Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s002`

> The Gray AW is not permitted to maintain, monitor, or control Inner Encryption Components or Red Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u010`

> 5.7 RED MANAGEMENT SERVICES

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u011.s001`

> Secure administration of Inner Encryption Components and continuous monitoring of the Red Network are essential roles provided by the Red Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u011.s002`

> Red Management Services are composed of a number of components that provide distinct security to the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u011.s003`

> As described below, this CP allows flexibility in the placement of some Red Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u001`

> 5.7.1 RED ADMINISTRATION MANAGEMENT COMPONENTS

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s001`

> The Red AWs maintain, monitor, and control all security functions for the Inner Encryption Components, Inner Firewall, and all Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004`

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u005.s001`

> Given the architecture of the solution, each layer has its own distinct administration LAN or VLAN; the Inner Encryption Component and supporting components are managed from the Red Management Services, and the Outer Encryption Component and supporting components are managed from the Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u005`

> MSC-SR-3 The time of day on the Inner Encryption Component and Red Management Services must be synchronized to a trusted time source located in the Red Network. T=O

## ROLE-gray-management: Gray Management Services

Kind: aggregate_component_service_role.

Aggregate services for secure Gray Network administration and monitoring. [Interpretation for review.]

Source wording: GRAY MANAGEMENT SERVICES, Gray Management Service, Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u022`

> 5.4 Gray Management Services ........................................................................................................ 17

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s007`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u007.s002`

> Gray Networks are composed of Gray data and Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s001`

> Gray Network components consist of the Outer Encryption Component, Gray Firewall, and Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s003`

> Gray Management Services are physically connected to the Gray Firewall and include, at a minimum, a AW that can be a physical workstation or Virtual Machine (VM).

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s004`

> The Gray Management Services may also include a Security Information and Event Management (SIEM) unless the SIEM is implemented in the Red Network in conjunction with a cross domain solution (CDS) (see CSfC Continuous Monitoring Annex).

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s006`

> As a result, neither Red nor Black AWs are permitted to manage the Outer Encryption Component, Gray Firewall, or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label008`

> Gray Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p014:f03:label013`

> Gray Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p015:f04:label009`

> Gray Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p017:f05:label012`

> Gray Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label016`

> Gray Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p018:f06:label028`

> Gray Management Services

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u007`

> 5.4 GRAY MANAGEMENT SERVICES

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u008.s001`

> Secure administration of components in the Gray Network and continuous monitoring of the Gray Network are essential roles provided by the Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u008.s002`

> Gray Management Services are composed of multiple components that provide distinct security to the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u008.s003`

> This CP allows flexibility in the placement of some Gray Management Services as described below.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u008.s004`

> The Gray Management Services are physically protected as classified devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u010.s001`

> The Gray AW maintains, monitors, and controls all security functionality for the Outer Encryption Component, Gray Firewall, and all Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u002.s002`

> The Red AWs are not permitted to maintain, monitor, or control Outer Encryption Components or Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u010.s004`

> During the provisioning process, the Security Administrator configures the Outer Firewall, Outer Encryption Component, Gray Firewall, Gray Management Services, Inner Encryption Component, Red Management Services and Inner Firewall in accordance with the requirements of this CP.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s003`

> Implementations may employ a SIEM in the Gray Management Services for log management of Gray infrastructure components except where AOs use a CDS to move Gray Network log data to a Red SIEM.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u005.s001`

> Given the architecture of the solution, each layer has its own distinct administration LAN or VLAN; the Inner Encryption Component and supporting components are managed from the Red Management Services, and the Outer Encryption Component and supporting components are managed from the Gray Management Services.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s001`

> The Gray AWs along with all Gray Management Services, are physically connected to the Gray Firewall, if required, or the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u006.s002`

> The Gray Firewall maintains separate Access Control Lists (ACLs) to permit management traffic to/from the Gray Management Services but prohibits such traffic from all other components.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s008`

> For example, a Gray AW residing within the Gray Management Services at the same site as the Outer Encryption Component need not use CNSA Suite algorithms since this traffic does not traverse an untrusted network.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

## ROLE-siem: Security Information and Event Management

Kind: device_or_service_role.

Collects and analyzes log data and provides alerts. [Interpretation for review.]

Source wording: SECURITY INFORMATION AND EVENT MANAGEMENT, SIEM, SIEMs, Security Information and Event Management.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u024`

> 5.4.2 Gray Security Information and Event Management (SIEM) ............................................... 17

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u029`

> 5.7.2 Red Security Information and Event Management (SIEM) ................................................. 19

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s004`

> The Gray Management Services may also include a Security Information and Event Management (SIEM) unless the SIEM is implemented in the Red Network in conjunction with a cross domain solution (CDS) (see CSfC Continuous Monitoring Annex).

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u007.s002`

> It includes the communications between a system administrator and a component, as well as the logs and other status information forwarded from a Solution Component to a SIEM, or similar repository.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u011`

> 5.4.2 GRAY SECURITY INFORMATION AND EVENT MANAGEMENT (SIEM)

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s002`

> Log data should be encrypted between the originating component and the Gray SIEM with SSHv2, TLS 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s002`

> The SIEM is configured to provide alerts for specific events including if the Outer Encryption Component or Gray Firewall receives and drops any unexpected traffic that could indicate a compromise.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s003`

> These functions can also be performed on a Red SIEM using an approved CDS, as described in the CSfC Continuous Monitoring Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s004`

> A Gray SIEM is not a mandatory component of the MSC Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u003`

> 5.7.2 RED SECURITY INFORMATION AND EVENT MANAGEMENT (SIEM)

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s002`

> Log data should be encrypted between the originating component and the Red SIEM with SSHv2, TLS 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s004`

> The SIEM is configured to provide alerts for specific events.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s003`

> Implementations may employ a SIEM in the Gray Management Services for log management of Gray infrastructure components except where AOs use a CDS to move Gray Network log data to a Red SIEM.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u016`

> MSC-DM-28 The AW must not also be used for provisioning, certificate registrations, and SIEM services. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p063:u029`

> SIEM Security Information and Event Management

## ROLE-red-siem: Red SIEM

Kind: device_or_service_role.

Collects Red-side logs and flow data; may receive Gray logs through an approved CDS. [Interpretation for review.]

Source wording: RED SECURITY INFORMATION AND EVENT MANAGEMENT, Red SIEM, Red SIEMs, Red Security Information and Event Management.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u029`

> 5.7.2 Red Security Information and Event Management (SIEM) ................................................. 19

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s003`

> These functions can also be performed on a Red SIEM using an approved CDS, as described in the CSfC Continuous Monitoring Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u003`

> 5.7.2 RED SECURITY INFORMATION AND EVENT MANAGEMENT (SIEM)

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s001`

> Red SIEMs collect and analyze log data and flow data from the Inner Encryption Components, the Inner Firewall and other Red Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u004.s002`

> Log data should be encrypted between the originating component and the Red SIEM with SSHv2, TLS 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s003`

> Implementations may employ a SIEM in the Gray Management Services for log management of Gray infrastructure components except where AOs use a CDS to move Gray Network log data to a Red SIEM.

## ROLE-gray-siem: Gray SIEM

Kind: device_or_service_role.

Collects Gray-side logs; explicitly not a mandatory component. [Interpretation for review.]

Source wording: GRAY SECURITY INFORMATION AND EVENT MANAGEMENT, Gray SIEM, Gray Security Information and Event Management.

`CSFC-MSC-1.3.0-4e40e3d83708:p004:u024`

> 5.4.2 Gray Security Information and Event Management (SIEM) ............................................... 17

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u011`

> 5.4.2 GRAY SECURITY INFORMATION AND EVENT MANAGEMENT (SIEM)

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s001`

> The Gray SIEM collects and analyzes log data from the Outer Encryption Component, Gray Firewall, and other Gray Management Service components.

`CSFC-MSC-1.3.0-4e40e3d83708:p024:u012.s002`

> Log data should be encrypted between the originating component and the Gray SIEM with SSHv2, TLS 1.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s004`

> A Gray SIEM is not a mandatory component of the MSC Solution.

## ROLE-authentication-server: Authentication Server

Kind: device_or_service_role.

Supports EAP-TLS mutual authentication between MACsec Devices. [Interpretation for review.]

Source wording: AS, ASs, Authentication Server, Authentication Servers, MSC AUTHENTICATION SERVER, MSC Authentication Server, authentication server.

`CSFC-MSC-1.3.0-4e40e3d83708:p005:u001`

> 5.8 MSC Authentication Server (AS) ................................................................................................. 19

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s005`

> If MACsec Devices are authenticating using certificates, the authentication server (AS) must not connect to both Gray and/or Red Networks.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u005`

> 5.8 MSC AUTHENTICATION SERVER (AS)

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s001`

> The MSC AS is responsible for mutual authentication between MACsec Devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s002`

> Authentication must be established between the MACsec device and the AS, where each MACsec device must perform the functions of a supplicant and authenticator.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s004`

> Objectively, the MSC Authentication Server should use CNSA 2.

`CSFC-MSC-1.3.0-4e40e3d83708:p034:u009`

> MSC-PS-17 Products used for the AS must be chosen from the list of ASs on the CSfC Components List. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p037:u003`

> MSC-SR-24 All solution components (Firewalls, VPN Gateways, Authentication Servers, etc) must use software and firmware signing algorithms in Table 2. O Optional

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u010`

> MSC-AA-1 The AS must be used to provide mutual authentication using EAP-TLS with device certificates between MACsec Devices. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u011`

> MSC-AA-2 The AS must only connect to one site’s network when a MACsec device is an Outer or Inner Encryption Component. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u012`

> MSC-AA-3 The MACsec Devices and the AS must use the CNSA 1.0 EAP-TLS Ciphersuite in Table 10. T MSC-AA-4

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u013`

> MSC-AA-4 The MACsec Devices and the AS must use the CNSA 2.0 EAP-TLS Ciphersuite in Table 11. O MSC-AA-3

`CSFC-MSC-1.3.0-4e40e3d83708:p062:u007`

> AS Authentication Server

## ROLE-supplicant: Supplicant

Kind: device_or_service_role.

MACsec Device authentication function; each device performs both supplicant and authenticator functions. [Interpretation for review.]

Source wording: supplicant.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s002`

> Authentication must be established between the MACsec device and the AS, where each MACsec device must perform the functions of a supplicant and authenticator.

## ROLE-authenticator: Authenticator

Kind: device_or_service_role.

MACsec Device authentication function; distinct from the Authentication Server. [Interpretation for review.]

Source wording: authenticator.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u006.s002`

> Authentication must be established between the MACsec device and the AS, where each MACsec device must perform the functions of a supplicant and authenticator.

## ROLE-key-server: Key Server

Kind: device_or_service_role.

MACsec Device designated to distribute Secure Association Keys to its peer. [Interpretation for review.]

Source wording: Key Server.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s004`

> For each MACsec tunnel, a Key Server is identified.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s005`

> The Key Server authenticates the other MACsec Device and issues a Secure Association Key to provide confidentiality and integrity for the MACsec tunnel.

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u011`

> MSC-MD-6 For each pair of MACsec Devices establishing an encryption tunnel, one of the two must be configured to be the Key Server by setting its Key Server value to 0 (zero). The other MACsec Device must have its Key Server value set to 1. If a Central Management Site is part of the MSC Solution, it must be the Key Server. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u013.s001`

> Key Server – The MACsec Device designated as the one responsible for distribution Secure Association Keys to the other MACsec Device.

## ROLE-ca: Certification Authority

Kind: device_or_service_role.

Issues certificates; preserve CA role separately from human CA Administrators. [Interpretation for review.]

Source wording: CA, CAs, Certificate Authority, Certification Authorities, Certification Authority.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s002`

> If Certification Authorities (CAs) are part of the MSC Solution, each site has the option to use either locally run CAs that they manage and control or, where available, enterprise CAs that are not necessarily managed by the Solution Owner.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s002`

> In the MSC Solution, Encryption Components at each site using public key certificates need to have the signing certificates and revocation information for the corresponding CAs used by the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s003`

> This high-level design requires cooperation between the various sites in the solution to ensure that all CAs used by each site are trusted at all the other sites.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s003`

> At least two CAs are needed; one for all the Inner Encryption Components and one for all the Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s004`

> If available, enterprise CAs should be used.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s005`

> If MACsec Devices are used on either or both layers and EAP-TLS is used for authentication, then CAs and an AS located at the Central site are required, otherwise, PSKs may be used for authentication for one of the layers of the solution and that layer would not require a CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s008`

> Given both cases, separate CAs, CAKs, and management devices are needed to manage the Inner Encryption Components at each security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s002`

> Two Inner Encryption Components for networks of different security levels will be unable to mutually authenticate with each other because they trust different CAs that do not have a trust relationship with one another or they use different CAKs that will not provide authentication.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s001`

> Additionally, filtering components are included between the components used for management of the Gray Networks themselves (namely, AWs and locally run CAs) and Inner Encryption Components that support Red Networks of a lower security level than the Red Network with the highest security level supported by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s002`

> In other words, AWs and locally run CAs on Gray Networks are treated as, and grouped with, the Inner Encryption Component for the Red Network with the highest security level.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s003`

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s005`

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s007`

> , Root CA certificate).

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s002`

> The Security Administrator delivers the Outer Encryption’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s002`

> The appropriate CA processes the CSR for each encryption component and returns a signed X.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s004`

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s006`

> , Root CA certificate).

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u009`

> MSC-VG-4 When using certificate-based authentication, a unique device certificate must be loaded onto each VPN Gateway along with the corresponding CA certificate chain, to include the Trust Anchor CA certificate. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u002`

> MSC-DM-14 AWs that interact with the Certificate Authority for the Outer VPN Gateways must be located on the Gray Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p059:u011.s001`

> Certification Authority (CA) – An authority trusted by one or more users to create and assign certificates.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u001.s001`

> CRL Distribution Point (CDP) – A web server that hosts a copy of a CRL issued by a CA for VPN Gateways to download (see CSfC Key Management Requirements Annex).

`CSFC-MSC-1.3.0-4e40e3d83708:p061:u005.s001`

> Registration Authority (RA) – An entity authorized by the CA to collect, verify, and submit information that is to be entered into public key certificates.

`CSFC-MSC-1.3.0-4e40e3d83708:p062:u010`

> CA Certification Authority

## ROLE-inner-ca: Inner CA

Kind: device_or_service_role.

CA associated with Inner Encryption Components. [Interpretation for review.]

Source wording: Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s002`

> The Security Administrator delivers the Outer Encryption’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

## ROLE-outer-ca: Outer CA

Kind: device_or_service_role.

CA associated with Outer Encryption Components. [Interpretation for review.]

Source wording: Outer CA, outer ca.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002`

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s002`

> The Security Administrator delivers the Outer VPN Gateway’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u013.s002`

> The Security Administrator delivers the Outer Encryption’s CSR to the Outer CA and the Inner VPN Gateway’s CSR to the Inner CA.

## ROLE-local-ca: Locally run CA

Kind: device_or_service_role.

Locally operated CA placement/management specialization. [Interpretation for review.]

Source wording: locally run CAs.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s002`

> If Certification Authorities (CAs) are part of the MSC Solution, each site has the option to use either locally run CAs that they manage and control or, where available, enterprise CAs that are not necessarily managed by the Solution Owner.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s001`

> Additionally, filtering components are included between the components used for management of the Gray Networks themselves (namely, AWs and locally run CAs) and Inner Encryption Components that support Red Networks of a lower security level than the Red Network with the highest security level supported by the solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p018:u001.s002`

> In other words, AWs and locally run CAs on Gray Networks are treated as, and grouped with, the Inner Encryption Component for the Red Network with the highest security level.

## ROLE-enterprise-ca: Enterprise CA

Kind: device_or_service_role.

Enterprise CA that need not be managed by the Solution Owner. [Interpretation for review.]

Source wording: enterprise CAs.

`CSFC-MSC-1.3.0-4e40e3d83708:p014:u006.s002`

> If Certification Authorities (CAs) are part of the MSC Solution, each site has the option to use either locally run CAs that they manage and control or, where available, enterprise CAs that are not necessarily managed by the Solution Owner.

`CSFC-MSC-1.3.0-4e40e3d83708:p015:u002.s004`

> If available, enterprise CAs should be used.

## ROLE-root-ca: Root CA

Kind: device_or_service_role.

Root CA is given as an example of a trust anchor in certificate-chain provisioning; the document does not make the terms exact synonyms. [Interpretation for review.]

Source wording: Root CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s007`

> , Root CA certificate).

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s006`

> , Root CA certificate).

## ROLE-signing-ca: Signing CA

Kind: device_or_service_role.

Certificate-signing CA role mentioned in provisioning and trust-chain setup. [Interpretation for review.]

Source wording: signing CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s005`

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u001.s004`

> The Security Administrator then installs the unique signed certificate and the certificate chain, which consists of the signing CA’s certificate and the Trust Anchor certificate (e.

## ROLE-kgs: Key Generation Solution

Kind: device_or_service_role.

Generates pre-shared CAKs and associated CKNs. [Interpretation for review.]

Source wording: KGS, Key Generation Solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:u009.s002`

> This CP also requires all CAKs and their associated Connectivity Key Names (CKNs) to be generated using an NSA-approved Key Generation Solution (KGS).

`CSFC-MSC-1.3.0-4e40e3d83708:p022:u004.s003`

> Mandatory aspects of the solution also include AWs, CAs for key management using Public Key Infrastructure (PKI), a KGS for generating pre- shared CAKs, and Gray Firewalls when networks of different security levels share the same Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p029:u012.s001`

> For provisioning MACsec PSK Encryption Components, the Security Administrator obtains a Symmetric Key from an NSA-approved KGS and applies them to each Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p041:u010`

> MSC-MD-5 MACsec Devices must have the length of the CKN set to a minimum of 16 bytes (128 bits) and generate the CKN using an NSA-approved KGS. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p063:u002`

> KGS Key Generation Solution

## ROLE-encapsulation-device: Encapsulation/Decapsulation Device

Kind: device_or_service_role.

Encapsulates inner MACsec traffic when the selected encryption component lacks that feature. [Interpretation for review.]

Source wording: Encapsulation/ Decapsulation Device, standalone device, standalone router or switch.

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s002`

> If this feature is not supported, a standalone device is needed to encapsulate the MACsec-encrypted data (see Figure 8).

`CSFC-MSC-1.3.0-4e40e3d83708:p019:u009.s003`

> If using a standalone device, the internal interface will be connected to the Inner MACsec Device and the external interface will be connected to the Outer Encryption Component.

`CSFC-MSC-1.3.0-4e40e3d83708:p020:f08:label005`

> Encapsulation/ Decapsulation Device

`CSFC-MSC-1.3.0-4e40e3d83708:p020:f08:label009`

> Encapsulation/ Decapsulation Device

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

`CSFC-MSC-1.3.0-4e40e3d83708:p042:u004`

> MSC-MD-13 If a standalone device is required to provide encapsulation of MACsec traffic between an Inner MACsec Device and an Outer Encryption Component, the standalone device must be considered a Solution Component when satisfying requirements in Section 11.1. T=O

## ROLE-router: Router

Kind: device_or_service_role.

Generic routing device; retain specializations and context rather than equating all routers. [Interpretation for review.]

Source wording: Router, router.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s004`

> This router is part of the solution only in the sense that it is part of the network infrastructure of the Gray Network; this CP does not levy any security requirements on the router/switch.

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label011`

> Router

`CSFC-MSC-1.3.0-4e40e3d83708:p022:f09:label018`

> Router

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002`

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s003`

> The screening router could be part of an existing Black Network (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s005`

> , Customer Edge Router), or could be added between Outer Encryption Components and existing Black Network components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s006`

> However, since the screening router would become part of a Black Network, it is not considered to be part of the MSC Solution itself.

## ROLE-gray-router: Gray Network router

Kind: device_or_service_role.

Selects a redundant Outer Encryption Component in the availability example. [Interpretation for review.]

Source wording: ordinary router, router/switch.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s003`

> Each site’s Gray Network contains an ordinary router between the Inner and Outer Encryption Components that selects which Outer Encryption Component to route outbound packets.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s004`

> This router is part of the solution only in the sense that it is part of the network infrastructure of the Gray Network; this CP does not levy any security requirements on the router/switch.

## ROLE-screening-router: Screening router

Kind: device_or_service_role.

Optional Black Network packet filter outside the MSC Solution boundary. [Interpretation for review.]

Source wording: screening router.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002`

> A screening router can be used to filter packets from Black Networks before they arrive at Outer Encryption Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s003`

> The screening router could be part of an existing Black Network (e.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s006`

> However, since the screening router would become part of a Black Network, it is not considered to be part of the MSC Solution itself.

## ROLE-customer-edge-router: Customer Edge Router

Kind: device_or_service_role.

Example of an existing Black Network screening router. [Interpretation for review.]

Source wording: Customer Edge Router.

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s005`

> , Customer Edge Router), or could be added between Outer Encryption Components and existing Black Network components.

## ROLE-switch: Switch

Kind: device_or_service_role.

Device alternative for standalone encapsulation or Gray infrastructure forwarding; switching as an activity is not an instance. [Interpretation for review.]

Source wording: router/switch, switch.

`CSFC-MSC-1.3.0-4e40e3d83708:p021:u008.s004`

> This router is part of the solution only in the sense that it is part of the network infrastructure of the Gray Network; this CP does not levy any security requirements on the router/switch.

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s003`

> If the selected VPN Gateway or MACsec Device does not have this feature, a separate standalone router or switch is necessary to provide encapsulation and all requirements for Solution Components in this CP must apply to it.

## ROLE-cds: Cross Domain Solution

Kind: device_or_service_role.

Controlled interface across security domains, including transfer of Gray logs to a Red SIEM. [Interpretation for review.]

Source wording: CDS, Cross Domain Solution, cross domain solution.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s004`

> The Gray Management Services may also include a Security Information and Event Management (SIEM) unless the SIEM is implemented in the Red Network in conjunction with a cross domain solution (CDS) (see CSfC Continuous Monitoring Annex).

`CSFC-MSC-1.3.0-4e40e3d83708:p025:u001.s003`

> These functions can also be performed on a Red SIEM using an approved CDS, as described in the CSfC Continuous Monitoring Annex.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s003`

> Implementations may employ a SIEM in the Gray Management Services for log management of Gray infrastructure components except where AOs use a CDS to move Gray Network log data to a Red SIEM.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u012`

> MSC-SR-22 If a CDS is being leveraged within the solution, then it must adhere with DoDI 8540.01, the DISN Connection Process Guide, and the CDS must be on the National Cross Domain Strategy Management Office CDS Baseline. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u002.s001`

> Cross Domain Solution (CDS) – A form of controlled interface that provides the ability to manually and/or automatically access and/or transfer information between different security domains.

`CSFC-MSC-1.3.0-4e40e3d83708:p062:u014`

> CDS Cross Domain Solution

## ROLE-cdp: CRL Distribution Point

Kind: device_or_service_role.

Web server hosting a CRL for VPN Gateways to download. [Interpretation for review.]

Source wording: CDP, CDPs, CRL Distribution Point.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u013`

> MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u012`

> MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u001.s001`

> CRL Distribution Point (CDP) – A web server that hosts a copy of a CRL issued by a CA for VPN Gateways to download (see CSfC Key Management Requirements Annex).

`CSFC-MSC-1.3.0-4e40e3d83708:p062:u013`

> CDP CRL Distribution Point

## ROLE-ocsp-responder: OCSP Responder

Kind: device_or_service_role.

Certificate status responder used for revocation checking. [Interpretation for review.]

Source wording: OCSP Responder, OCSP Responders.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u010`

> MSC-SR-8 All physical paths within a Gray Network between a CA, a AW, or a CRL Distribution Point (CDP)/OCSP Responder and an Inner Encryption Component for Red Networks of different security levels must include a Gray Firewall. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u012`

> MSC-VG-7 VPN Gateway authentication must include a check that the certificate is not revoked, which can include a CRL, OCSP Responder, or other similar revocation reporting mechanism. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u013`

> MSC-PF-15 If the CDP/OCSP is on the gray data plane, the Gray Network interfaces of Outer VPN Gateways must T=O allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and the CDPs/OCSP Responders) and block all other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

`CSFC-MSC-1.3.0-4e40e3d83708:p046:u012`

> MSC-PF-25 If a Gray Firewall is required, the Gray Firewall must allow HTTP traffic that is necessary to perform revocation checking for the Inner encryption layer (i.e., requests/replies between the Inner VPN Gateways and CDPs/OCSP Responders) and block all T=O other HTTP traffic. Refer to IETF RFC 5280 and IETF RFC 6960 for further details on this type of traffic.

## ROLE-ips: Intrusion Prevention System

Kind: device_or_service_role.

Optional product-selection category in MSC-PS-5. [Interpretation for review.]

Source wording: IPS, IPSs, Intrusion Prevention System, Intrusion Prevention Systems.

`CSFC-MSC-1.3.0-4e40e3d83708:p033:u009`

> MSC-PS-5 Intrusion Prevention Systems (IPSs) must be chosen from the list of IPSs on the CSfC Components List. O Optional

`CSFC-MSC-1.3.0-4e40e3d83708:p062:u046`

> IPS Intrusion Prevention System

## ROLE-aw-host: Host/server for AW virtual machines

Kind: management_or_realization_facet.

Physical host/server used to host management or AW virtual machines; restrictions preserve dedicated functions. [Interpretation for review.]

Source wording: Hosts/servers, hosts/servers, physical host/server.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s001`

> AWs may be virtual machines (VMs) on a physical host/server that is dedicated to hosting AWs VMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s003`

> A physical host/server that hosts AWs VMs may not host VMs used for non-CSfC purposes.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u017`

> MSC-DM-2 AWs (or hosts/servers hosting VMs serving as AWs) must physically reside within a protected facility where CSfC solution(s) are managed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u011`

> MSC-DM-23 Hosts/servers for management VMs may not host VMs that perform non-CSfC functions. T=O

## ROLE-virtual-machine: Virtual Machine

Kind: management_or_realization_facet.

Virtual implementation form for management services and AWs. [Interpretation for review.]

Source wording: VM, VMs, Virtual Machine, virtual machines.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s003`

> Gray Management Services are physically connected to the Gray Firewall and include, at a minimum, a AW that can be a physical workstation or Virtual Machine (VM).

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s001`

> AWs may be virtual machines (VMs) on a physical host/server that is dedicated to hosting AWs VMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s003`

> A physical host/server that hosts AWs VMs may not host VMs used for non-CSfC purposes.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u017`

> MSC-DM-2 AWs (or hosts/servers hosting VMs serving as AWs) must physically reside within a protected facility where CSfC solution(s) are managed. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u011`

> MSC-DM-23 Hosts/servers for management VMs may not host VMs that perform non-CSfC functions. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p063:u040`

> VM Virtual Machine

## ROLE-physical-workstation: Physical workstation

Kind: management_or_realization_facet.

Physical implementation form; may host an AW or another explicitly separated function. [Interpretation for review.]

Source wording: physical workstation, separate workstations, workstations used.

`CSFC-MSC-1.3.0-4e40e3d83708:p011:u009.s003`

> Gray Management Services are physically connected to the Gray Firewall and include, at a minimum, a AW that can be a physical workstation or Virtual Machine (VM).

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p047:u016`

> MSC-DM-1 If using physical AWs, they must be dedicated for the purposes given in this CP and must be physically separated from workstations used to manage non-CSfC solutions. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

## ROLE-enrollment-server: Enrollment server

Kind: device_or_service_role.

Enrollment function mentioned in restrictions on cohosting management functions. [Interpretation for review.]

Source wording: enrollment or provisioning servers, enrollment,.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

## ROLE-provisioning-server: Provisioning server

Kind: device_or_service_role.

Provisioning function that must be separated from AW functions. [Interpretation for review.]

Source wording: provisioning servers, provisioning,.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u016`

> MSC-DM-28 The AW must not also be used for provisioning, certificate registrations, and SIEM services. T=O

## ROLE-certificate-registration: Certificate registration component

Kind: device_or_service_role.

Certificate-registration function separated from AW functions; exact product is unspecified. [Interpretation for review.]

Source wording: CA registration, certificate registrations.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s002`

> A physical host/server that hosts AWs VMs must not host VMs that are used for enrollment or provisioning servers, certificate registrations, or SIEMs.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u004.s004`

> If an AW is a physical workstation, then that workstation cannot also be used for provisioning, enrollment, certificate registrations, SIEM services, or for any non- CSfC functions.

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u012`

> MSC-DM-24 VMs that perform management services must not also perform other functions within the solution (i.e., provisioning, enrollment, CA registration, SIEM, etc. must be performed by separate workstations or VMs). T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p049:u016`

> MSC-DM-28 The AW must not also be used for provisioning, certificate registrations, and SIEM services. T=O

## ROLE-registration-authority: Registration Authority

Kind: mixed_authority_role.

Mixed hardware, software, and personnel authority collecting and submitting certificate information; device realization is unspecified. [Interpretation for review.]

Source wording: RA, Registration Authority.

The glossary includes individuals as well as hardware/software. Only the hardware/software function is within the device-role inventory.

`CSFC-MSC-1.3.0-4e40e3d83708:p061:u005.s001`

> Registration Authority (RA) – An entity authorized by the CA to collect, verify, and submit information that is to be entered into public key certificates.

`CSFC-MSC-1.3.0-4e40e3d83708:p061:u005.s002`

> The term RA refers to hardware, software, and individuals that collectively perform this function.

`CSFC-MSC-1.3.0-4e40e3d83708:p063:u024`

> RA Registration Authority

## ROLE-trusted-time-source: Trusted time source

Kind: device_or_service_role.

Trusted time source on the Red Network for Red components or on the Gray Management Network for Gray components. [Interpretation for review.]

Source wording: trusted time source.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u005`

> MSC-SR-3 The time of day on the Inner Encryption Component and Red Management Services must be synchronized to a trusted time source located in the Red Network. T=O

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u006`

> MSC-SR-4 The time of day on the Outer Encryption Component, Gray Management Services and Gray Firewall (if present) must be synchronized to a trusted time source located in the Gray Management Network. T=O

## ROLE-dns-server: DNS server

Kind: device_or_service_role.

Server referenced through configured DNS server addresses; not assigned an explicit deployment location. [Interpretation for review.]

Source wording: DNS server.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u010`

> MSC-SR-20 DNS server addresses on Solution Components must be specified or DNS services must be disabled. T=O

## ROLE-control-plane-service: Control plane network service

Kind: device_or_service_role.

Inside-network service category; NTP is an example rather than a new named device instance. [Interpretation for review.]

Source wording: Network services provided by control plane.

`CSFC-MSC-1.3.0-4e40e3d83708:p035:u003`

> MSC-SR-1 Network services provided by control plane protocols (such as NTP) must be located on the inside network (i.e., Gray Network for Outer Encryption Component and Red Network for Inner Encryption Component). T=O

## ROLE-third-party-server: Third-party server

Kind: device_or_service_role.

External server contact category blocked or disabled for Outer Encryption Components. [Interpretation for review.]

Source wording: third party server, third-party server.

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u004`

> MSC-PF-6 Any service or feature that allows an Outer Encryption Component to contact a third-party server (such as one maintained by the manufacturer) must be blocked. T MSC-PF-7

`CSFC-MSC-1.3.0-4e40e3d83708:p045:u005`

> MSC-PF-7 Any service or feature that allows an Outer Encryption Component to contact a third party server (such as one maintained by the manufacturer) must be disabled. O MSC-PF-6

## ROLE-end-user-device: End user device

Kind: device_or_service_role.

Device category in combined CSfC solutions referenced by MSC-SR-13. [Interpretation for review.]

Source wording: end user devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u003`

> MSC-SR-13 If the MSC Solution is combined with other CSfC data-in-transit solutions that include end user devices, the Inner Firewall requirements from that CP must be followed. T=O

## ROLE-high-assurance-encryptor: High Assurance encryptor

Kind: device_or_service_role.

Example approved protection for remote administration; not equated to an MSC encryption component. [Interpretation for review.]

Source wording: High Assurance encryptor.

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u007`

> MSC-DM-8 All administration of Solution Components must securely be performed from an AW remotely using an NSA-approved solution (e.g., CP or High Assurance encryptor), or by managing the Solution Components locally. T=O

## ROLE-government-product: NSA-certified Government-off-the-Shelf product

Kind: device_or_service_role.

Alternative approved egress product in the MSC-SR-14 footnote. [Interpretation for review.]

Source wording: NSA-certified product.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u015.s002`

> In particular, it is acceptable for a given site to have both an egress path via an NSA-certified product and an egress path via a CSfC Solution conforming to a CP.

## ROLE-locally-managed-device: Locally Managed Device

Kind: management_or_realization_facet.

Management-mode role defined by a hardwired AW connection. [Interpretation for review.]

Source wording: Locally Managed Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u014.s001`

> Locally Managed Device – A device that is being managed by the direct connection of the AW to the device in a hardwired fashion (such as a console cable).

`CSFC-MSC-1.3.0-4e40e3d83708:p061:u006.s001`

> Remotely Managed Device – A device that is being managed by any other method besides that given in the definition of a Locally Managed Device.

## ROLE-remotely-managed-device: Remotely Managed Device

Kind: management_or_realization_facet.

Management-mode role defined by methods other than a local hardwired AW connection. [Interpretation for review.]

Source wording: Remotely Managed Device.

`CSFC-MSC-1.3.0-4e40e3d83708:p061:u006.s001`

> Remotely Managed Device – A device that is being managed by any other method besides that given in the definition of a Locally Managed Device.

## ROLE-auxiliary-network-device: Auxiliary network device

Kind: device_or_service_role.

Generic supporting device category in Security Administrator duties. [Interpretation for review.]

Source wording: auxiliary network devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p054:u011.s001`

> 4) Employ adequate defenses of auxiliary network devices to enable proper and secure functionality of the MSC Solution.

## ROLE-authentication-service: Infrastructure authentication service

Kind: device_or_service_role.

Service used for access to infrastructure components under MSC-GD-27; not assumed identical to the MACsec AS. [Interpretation for review.]

Source wording: authentication service.

`CSFC-MSC-1.3.0-4e40e3d83708:p052:u009`

> MSC-GD-27 All infrastructure components must use an authentication service on their respective network/domain in order to access the Infrastructure component of the respective network/domain. O MSC-GD-21

## ROLE-network-administration-device: Network administration device

Kind: device_or_service_role.

Generic administrative device wording in MSC-DM-7; correspondence with AW is not explicitly defined. [Interpretation for review.]

Source wording: network administration device.

`CSFC-MSC-1.3.0-4e40e3d83708:p048:u006`

> MSC-DM-7 All components must be configured to restrict the IP address range for the network administration device to the smallest range possible. Note that locally managing Solution Components is also acceptable. T=O

## ROLE-infrastructure-component: Infrastructure component

Kind: device_or_service_role.

Generic infrastructure category in password, authentication-service, inventory, and inspection requirements. [Interpretation for review.]

Source wording: Infrastructure component, infrastructure components, infrastructure hardware.

`CSFC-MSC-1.3.0-4e40e3d83708:p030:u003.s003`

> Implementations may employ a SIEM in the Gray Management Services for log management of Gray infrastructure components except where AOs use a CDS to move Gray Network log data to a Red SIEM.

`CSFC-MSC-1.3.0-4e40e3d83708:p052:u003`

> MSC-GD-21 All infrastructure components must implement a password of at least 112 random bits. Passwords should be generated using an approved password generator. See CSfC Key Management Requirements Annex, Appendix A for more information. T MSC-GD-27

`CSFC-MSC-1.3.0-4e40e3d83708:p052:u009`

> MSC-GD-27 All infrastructure components must use an authentication service on their respective network/domain in order to access the Infrastructure component of the respective network/domain. O MSC-GD-21

`CSFC-MSC-1.3.0-4e40e3d83708:p055:u014`

> MSC-RB-6 Administrators must periodically inspect the physical attributes of infrastructure hardware for signs of tampering or other unauthorized changes. T=O

## ROLE-network-device: Network device

Kind: device_or_service_role.

Generic device category used in DNS-service restrictions and protocol discussion. [Interpretation for review.]

Source wording: network devices.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u009.s002`

> This allows IKEv2 messages to traverse network devices that do not allow IP fragments to pass through.

`CSFC-MSC-1.3.0-4e40e3d83708:p036:u009`

> MSC-SR-19 DNS lookup services on network devices must be disabled. O Optional

`CSFC-MSC-1.3.0-4e40e3d83708:p054:u011.s001`

> 4) Employ adequate defenses of auxiliary network devices to enable proper and secure functionality of the MSC Solution.

## ROLE-perimeter-device: Perimeter device

Kind: device_or_service_role.

Outer Encryption Component placement facet when no Outer Firewall is present. [Interpretation for review.]

Source wording: perimeter device.

`CSFC-MSC-1.3.0-4e40e3d83708:p023:u009.s001`

> The Outer Encryption Component may be a perimeter device (if the Outer Firewall is not present) and more exposed to external attacks.

## ROLE-key-management-component: Key and certificate management component

Kind: device_or_service_role.

Component category whose detailed requirements are relocated to separate annexes. [Interpretation for review.]

Source wording: KEY AND CERTIFICATE MANAGEMENT COMPONENTS, Key and Certificate Management Components.

`CSFC-MSC-1.3.0-4e40e3d83708:p005:u002`

> 5.9 Key and Certificate Management Components .......................................................................... 19

`CSFC-MSC-1.3.0-4e40e3d83708:p026:u007`

> 5.9 KEY AND CERTIFICATE MANAGEMENT COMPONENTS

## ROLE-trust-anchor-ca: Trust Anchor CA

Kind: device_or_service_role.

CA whose certificate is installed as the trust anchor under MSC-VG-4; Root CA remains a separately preserved example rather than an exact alias. [Interpretation for review.]

Source wording: Trust Anchor CA.

`CSFC-MSC-1.3.0-4e40e3d83708:p038:u009`

> MSC-VG-4 When using certificate-based authentication, a unique device certificate must be loaded onto each VPN Gateway along with the corresponding CA certificate chain, to include the Trust Anchor CA certificate. T=O

## ROLE-password-generator: Approved password generator

Kind: device_or_service_role.

Generates passwords as recommended by MSC-GD-21; the document does not specify a hardware or software realization. [Interpretation for review.]

Source wording: approved password generator.

`CSFC-MSC-1.3.0-4e40e3d83708:p052:u003`

> MSC-GD-21 All infrastructure components must implement a password of at least 112 random bits. Passwords should be generated using an approved password generator. See CSfC Key Management Requirements Annex, Appendix A for more information. T MSC-GD-27

## ROLE-log-repository: Log and status repository

Kind: device_or_service_role.

Receives logs and status information as an alternative to a SIEM; its implementation is unspecified. [Interpretation for review.]

Source wording: similar repository.

`CSFC-MSC-1.3.0-4e40e3d83708:p012:u007.s002`

> It includes the communications between a system administrator and a component, as well as the logs and other status information forwarded from a Solution Component to a SIEM, or similar repository.

## ROLE-testing-equipment: Testing equipment

Kind: device_or_service_role.

Equipment available for gray-box testing inside and outside the developed solution; no particular product is specified. [Interpretation for review.]

Source wording: testing equipment.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u007.s004`

> In addition, the use of any and all testing equipment and/or testing software used inside and outside the developed solution is available.

## ROLE-testing-software: Testing software

Kind: device_or_service_role.

Software available for gray-box testing inside and outside the developed solution; no particular product is specified. [Interpretation for review.]

Source wording: testing software.

`CSFC-MSC-1.3.0-4e40e3d83708:p060:u007.s004`

> In addition, the use of any and all testing equipment and/or testing software used inside and outside the developed solution is available.

## ROLE-ike-initiator: IKEv2 initiator

Kind: protocol_endpoint_role.

Protocol endpoint role that sends the initiator messages in the described IKE_SA_INIT exchange. The source does not identify Bob or Alice as that endpoint. [Interpretation for review.]

Source wording: initiator.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s002`

> In particular, if ML- KEM-1024 were used in the initial IKEv2 Security Association (SA) key exchange (IKE_SA_INIT), the sizes of its public key and ciphertext would cause the initiator and responder messages to exceed the typical path Maximum Transmission Unit (MTU) and necessitate IP-level fragmentation.

## ROLE-ike-responder: IKEv2 responder

Kind: protocol_endpoint_role.

Protocol endpoint role that sends the responder messages in the described IKE_SA_INIT exchange. The source does not identify Bob or Alice as that endpoint. [Interpretation for review.]

Source wording: responder.

`CSFC-MSC-1.3.0-4e40e3d83708:p027:u008.s002`

> In particular, if ML- KEM-1024 were used in the initial IKEv2 Security Association (SA) key exchange (IKE_SA_INIT), the sizes of its public key and ciphertext would cause the initiator and responder messages to exceed the typical path Maximum Transmission Unit (MTU) and necessitate IP-level fragmentation.
