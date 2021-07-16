/*!
* ============================================================================
*
* Flat FortiGate Policy
*
* flatFortiGatePolicy.js
*
* Copyright (c) 2021 joelob99
*
* Released under the MIT License, see LICENSE.txt.
*
* History
*   2021-07-16: First Release. (flatAsaAcl.js v0.9.2 base)
*
* @file This script flattens firewall policies of the FortiGate configuration.
*       Also, it can look up the specified addresses in flattened firewall
*       policies to confirm whether the address is matched.
* @copyright joelob99 2021
* @license MIT License
* @version v0.9.0
*
* ============================================================================
*/

'use strict';

/**
* Policy types.
*
* @const {number}
*/
const POLICY_TYPE_4TO4  = 1;
const POLICY_TYPE_6TO6  = 2;
const POLICY_TYPE_6TO4  = 3;
const POLICY_TYPE_4TO6  = 4;
const POLICY_TYPE_4TO4M = 5;
const POLICY_TYPE_6TO6M = 6;

/**
* Bit flags of protocol type.
*
* @const {number}
*/
const PROTOCOL_TYPE_BIT_NONE         = 0x0000;
const PROTOCOL_TYPE_BIT_IP           = 0x0001;
const PROTOCOL_TYPE_BIT_ICMP_ICMP6   = 0x0002;
const PROTOCOL_TYPE_BIT_TCP_UDP_SCTP = 0x0004;
const PROTOCOL_TYPE_BIT_UNSUPPORTED  = 0x1000;

/**
* Address types for lookup.
*
* @const {number}
*/
const LOOKUP_ADDRESS_TYPE_UNKNOWN = 0;
const LOOKUP_ADDRESS_TYPE_IPV4    = 1;
const LOOKUP_ADDRESS_TYPE_IPV6    = 2;
const LOOKUP_ADDRESS_TYPE_FQDN    = 3;
const LOOKUP_ADDRESS_TYPE_GEO     = 4;

/**
* Column number of normalized policy.
*
* @const {number}
*/
const NMCOL_DOM_NAME        = 0;
const NMCOL_SRC_INTF        = 1;
const NMCOL_DST_INTF        = 2;
const NMCOL_POL_TYPE        = 3;
const NMCOL_POL_ID          = 4;
const NMCOL_POL_NAME        = 5;
const NMCOL_POL_LINE        = 6;
const NMCOL_ACTION          = 7;
const NMCOL_PROTOCOL        = 8;
const NMCOL_SRC_ADDR        = 9;
const NMCOL_SRC_PORT        = 10;
const NMCOL_DST_ADDR        = 11;
const NMCOL_DST_PORT        = 12;
const NMCOL_SERVICE_DSTADDR = 13;
const NMCOL_ICMPTYCD        = 14;
const NMCOL_SRCADDR_NEGATE  = 15;
const NMCOL_DSTADDR_NEGATE  = 16;
const NMCOL_SERVICE_NEGATE  = 17;
const NMCOL_STATUS          = 18;
const NMCOL_LOG             = 19;
const NMCOL_SCHEDULE        = 20;
const NMCOL_COMMENT         = 21;

/*
* ============================================================================
* Prototype functions
* ============================================================================
*/

/**
* This function returns the new string stripped of the argument string from
* both ends.
*
* @param {string} str
* @return {string} New string stripped of the argument string.
*
*/
if (!String.prototype.trimString) {
    String.prototype.trimString = function(str) { // eslint-disable-line no-extend-native
        return this.substring(this.startsWith(str) ? str.length : 0, this.length - (this.endsWith(str) ? str.length : 0));
    };
}

/**
* This function returns the new array removed duplicate elements.
*
* @return {Array} New array removed duplicate elements.
*
*/
if (!Array.prototype.unique) {
    Array.prototype.unique = function() { // eslint-disable-line no-extend-native
        return Array.from(new Set(this));
    };
}

/**
* This function returns the last element of this array.
*
* @return {(Array|undefined)} Last element of this array.
*
*/
if (!Array.prototype.last) {
    Array.prototype.last = function() { // eslint-disable-line no-extend-native
        return this[this.length - 1];
    };
}

/*
* ============================================================================
* Class
* ============================================================================
*/

/**
* This class operates wildcard fqdn.
*
*/
class WildcardFQDN {
    /**
    * This constructor defines variables for WildcardFQDN class.
    *
    */
    constructor() {
        this.re = undefined;
    }

    /**
    * This setter creates an instance of the RegExp object using the specified
    * wildcard FQDN.
    *
    * @param {string} strWildcardFqdn
    *
    */
    set name(strWildcardFqdn) {
        const strRegex = '^' + strWildcardFqdn.replaceAll('.', '\\.').replaceAll('*', '[^\\.]*') + '$';
        this.re = new RegExp(strRegex);
    }

    /**
    * This method returns true if the specified string matches with the
    * wildcard FQDN set by name method. Otherwise, it is false.
    *
    * @param {string} strTestFqdn
    * @return {boolean}
    *   true if the specified string matches with the wildcard FQDN set by
    *   name method. Otherwise, it is false.
    *
    * @example
    *   name(strWildcardFqdn) strTestFqdn          Return
    *   -------------------------------------------------
    *   '*.example.com'       'example.com'     -> false
    *   '*.example.com'       '.example.com'    -> true
    *   '*.example.com'       'www.example.com' -> true
    */
    test(strTestFqdn) {
        return this.re.test(strTestFqdn);
    }
}

/**
* This class operates the IPv4 range.
*
*/
class IPv4Range { // eslint-disable-line no-unused-vars
    /**
    * This constructor defines variables for IPv4Range class.
    *
    */
    constructor() {
        this.intStartAddr = undefined;
        this.intEndAddr = undefined;
        this.arraySubnet = undefined;
    }

    /**
    * This setter saves integers of the start address and end address and the
    * subnet array for the specified IPv4 range string.
    *
    * @param {string} strIPv4Range
    *
    */
    set iprange(strIPv4Range) {
        const array = strIPv4Range.indexOf('-') != -1 ? strIPv4Range.split('-') : [strIPv4Range];
        this.intStartAddr = toIPv4AddrInteger(array[0]);
        this.intEndAddr = array[1] ? toIPv4AddrInteger(array[1]) : toIPv4AddrInteger(array[0]);

        this.arraySubnet = [];
        makeIPv4SubnetFromRange(this.intStartAddr, this.intEndAddr, this.arraySubnet);
    }

    /**
    * This method returns true if this IPv4 range is included in the specified
    * segment. Otherwise, it is false.
    *
    * @param {string} strTestSegment
    * @return {boolean}
    *   true if this IPv4 range is included in the specified segment.
    *   Otherwise, it is false.
    *
    * @example
    *   iprange(strIPv4Range)       strTestSegment      Return
    *   ------------------------------------------------------
    *   '192.168.0.1'               '192.168.0.0/31' -> true
    *   '192.168.0.1'               '192.168.0.0/32' -> false
    *   '192.168.0.1-192.168.0.100' '192.168.0.0/24' -> true
    *   '192.168.0.1-192.168.0.100' '192.168.0.0/28' -> false
    */
    isIncludedInSegment(strTestSegment) {
        for (let i=0; i<this.arraySubnet.length; ++i) {
            if (!isIPv4WithPrefixLengthIncludedInSegment(this.arraySubnet[i], strTestSegment)) {
                return false;
            }
        }
        return true;
    }

    /**
    * This method returns true if this IPv4 range is matched in the specified
    * Fortinet-style wildcard address. Otherwise, it is false.
    *
    * @param {string} strTestWildcardAddr
    * @return {boolean}
    *   true if this IPv4 range is included in the specified wildcard address.
    *   Otherwise, it is false.
    *
    * @example
    *   iprange(strIPv4Range)       strTestWildcardAddr              Return
    *   -------------------------------------------------------------------
    *   '192.168.0.1'               '192.168.0.0/255.255.255.254' -> true
    *   '192.168.0.1'               '192.168.0.0/255.255.255.255' -> false
    *   '192.168.0.1-192.168.0.100' '192.168.0.0/255.255.255.0'   -> true
    *   '192.168.0.1-192.168.0.100' '192.168.0.0/255.255.255.240' -> false
    */
    isMatchedInFortinetWildcardAddr(strTestWildcardAddr) {
        for (let i=0; i<this.arraySubnet.length; ++i) {
            if (!isIPv4WithPrefixLengthIncludedInFortinetWildcardAddr(this.arraySubnet[i], strTestWildcardAddr)) {
                return false;
            }
        }
        return true;
    }

    /**
    * This method returns true if this IPv4 range is included in the specified
    * IPv4 range. Otherwise, it is false.
    *
    * @param {string} strTestRange
    * @return {boolean}
    *   true if this IPv4 range is included in the specified IPv4 range.
    *   Otherwise, it is false.
    *
    * @example
    *   iprange(strIPv4Range)       strTestRange                   Return
    *   -----------------------------------------------------------------
    *   '192.168.0.1'               '192.168.0.0-192.168.0.1'   -> true
    *   '192.168.0.1'               '192.168.0.0-192.168.0.0'   -> false
    *   '192.168.0.1-192.168.0.100' '192.168.0.0-192.168.0.255' -> true
    *   '192.168.0.1-192.168.0.100' '192.168.0.0-192.168.0.15'  -> false
    */
    isIncludedInRange(strTestRange) {
        const array = strTestRange.split('-');
        return (this.intStartAddr >= toIPv4AddrInteger(array[0]) && this.intEndAddr <= toIPv4AddrInteger(array[1]));
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands actions for
* configuration. The subclass derived from this class defines those detailed
* actions for each configuration.
*
*/
class ConfigEdit {
    /**
    * This constructor defines variables for ConfigEdit class.
    *
    */
    constructor() {
        this.strDomainName = '';
        this.strEditName = '';
        this.objParam = {};
    }

    /**
    * This setter saves the domain name.
    *
    * @param {string} strDomainName - Domain name.
    *
    */
    set DomainName(strDomainName) {
        this.strDomainName = strDomainName;
    }

    /**
    * This method should be called when the 'config firewall' statement is
    * found in the FortiGate configuration. Subclass calls superclass before
    * its initing.
    *
    */
    init() {
    }

    /**
    * This method should be called when the 'edit' statement is found in the
    * FortiGate configuration. Subclass calls superclass before its beginning
    * and then initializes this.objParam.
    *
    * @param {string} strEditName - Name or ID entered in 'edit' command.
    *
    */
    begin(strEditName) {
        this.strEditName = strEditName;
    }

    /**
    * This method should be called when the 'next' statement is found in the
    * FortiGate configuration. Subclass normalizes this.objParam and saves it
    * into g_Domain_Data.
    *
    */
    end() {
    }

    /**
    * This method should be called when the 'set' statement is found in the
    * FortiGate configuration. Subclass sets the found parameters to
    * this.objParam.
    *
    * @param {string} strLine - Line of the configuration.
    * @param {Array} arrayToken - Array of the line's tokens.
    *
    */
    set(strLine, arrayToken) { // eslint-disable-line no-unused-vars
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for following
* configurations.
*
*   'config firewall service custom'
*   'config firewall service group'
*
* @extends ConfigEdit
*
*/
class FirewallService extends ConfigEdit {
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall service custom'
*
* @extends FirewallService
*
*/
class FirewallServiceCustom extends FirewallService {
    /**
    * This method initializes the parameter object for FirewallServiceCustom
    * class.
    *
    * @param {string} strEditName - Name or ID entered in 'edit' command.
    *
    */
    begin(strEditName) {
        super.begin(strEditName);
        this.objParam['protocol'] = '';
        this.objParam['protocol_number'] = '';
        this.objParam['tcp_portrange'] = '';
        this.objParam['udp_portrange'] = '';
        this.objParam['sctp_portrange'] = '';
        this.objParam['iprange'] = '';
        this.objParam['fqdn'] = '';
        this.objParam['icmptype'] = '';
        this.objParam['icmpcode'] = '';
        this.objParam['comment'] = '';
    }

    /**
    * This method normalizes the parameter object for FirewallServiceCustom
    * class and saves it into g_Domain_Data.
    *
    */
    end() {
        if (this.objParam['protocol'] === '') {
            this.objParam['protocol'] = 'TCP/UDP/SCTP';
        }
        g_Domain_Data[this.strDomainName].service_custom[this.strEditName] = normalizeFirewallServiceCustom(this.objParam);
    }

    /**
    * This method sets the parameter of the 'firewall service custom' object
    * to this class's parameter object.
    *
    * @param {string} strLine - Line of the configuration.
    * @param {Array} arrayToken - Array of the line's tokens.
    *
    */
    set(strLine, arrayToken) {
        if (arrayToken[2]) {
            const intIndexOfParamValue = arrayToken[0].length + arrayToken[1].length + 2;
            const strParam = arrayToken[1].replaceAll('-', '_');

            switch (arrayToken[1]) {
            case 'protocol':
            case 'protocol-number':
            case 'tcp-portrange':
            case 'udp-portrange':
            case 'sctp-portrange':
            case 'iprange':
            case 'fqdn':
            case 'icmptype':
            case 'icmpcode':
            case 'comment':
                this.objParam[strParam] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            }
        }
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall service group'
*
* @extends FirewallService
*
*/
class FirewallServiceGroup extends FirewallService {
    /**
    * This method initializes the parameter object for FirewallServiceGroup
    * class.
    *
    * @param {string} strEditName - Name or ID entered in 'edit' command.
    *
    */
    begin(strEditName) {
        super.begin(strEditName);
        this.objParam['member'] = '';
        this.objParam['comment'] = '';
    }

    /**
    * This method normalizes the parameter object for FirewallServiceGroup
    * class and saves it into g_Domain_Data.
    *
    */
    end() {
        g_Domain_Data[this.strDomainName].service_group[this.strEditName] = normalizeFirewallServiceGroup(this.objParam, g_Domain_Data[this.strDomainName].service_custom, g_Domain_Data[this.strDomainName].service_group);
    }

    /**
    * This method sets the parameter of the 'firewall service group' object to
    * this class's parameter object.
    *
    * @param {string} strLine - Line of the configuration.
    * @param {Array} arrayToken - Array of the line's tokens.
    *
    */
    set(strLine, arrayToken) {
        if (arrayToken[2]) {
            const intIndexOfParamValue = arrayToken[0].length + arrayToken[1].length + 2;

            switch (arrayToken[1]) {
            case 'member':
                this.objParam['member'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            case 'comment':
                this.objParam['comment'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            }
        }
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for following
* configurations.
*
*   'config firewall address'
*   'config firewall address6'
*
* @extends ConfigEdit
*
*/
class FirewallAddress extends ConfigEdit {
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall address'
*
* @extends FirewallAddress
*
*/
class FirewallAddress4 extends FirewallAddress {
    /**
    * This method initializes the parameter object for FirewallAddress4 class.
    *
    * @param {string} strEditName - Name or ID entered in 'edit' command.
    *
    */
    begin(strEditName) {
        super.begin(strEditName);
        this.objParam['type'] = 'ipmask';
        this.objParam['param1'] = '';
        this.objParam['param2'] = '';
        this.objParam['comment'] = '';
    }

    /**
    * This method normalizes the parameter object for FirewallAddress4 class
    * and saves it into g_Domain_Data.
    *
    */
    end() {
        if (this.objParam['type'] === 'ipmask' || this.objParam['type'] === 'iprange' || this.objParam['type'] === 'wildcard') {
            if (this.objParam['param1'] === '') {
                this.objParam['param1'] = '0.0.0.0';
            }
            if (this.objParam['param2'] === '') {
                this.objParam['param2'] = '0.0.0.0';
            }
        }
        g_Domain_Data[this.strDomainName].address4[this.strEditName] = normalizeFirewallIPv4Address(this.objParam);
    }

    /**
    * This method sets the parameter of the 'firewall address' object to this
    * class's parameter object.
    *
    * @param {string} strLine - Line of the configuration.
    * @param {Array} arrayToken - Array of the line's tokens.
    *
    */
    set(strLine, arrayToken) {
        if (arrayToken[2]) {
            const intIndexOfParamValue = arrayToken[0].length + arrayToken[1].length + 2;

            switch (arrayToken[1]) {
            case 'type':
                this.objParam['type'] = arrayToken[2];
                break;
            case 'subnet':
                this.objParam['param1'] = arrayToken[2];
                this.objParam['param2'] = arrayToken[3] ? arrayToken[3] : '255.255.255.255';
                break;
            case 'wildcard':
                this.objParam['param1'] = arrayToken[2];
                this.objParam['param2'] = arrayToken[3] ? arrayToken[3] : '0.0.0.0';
                break;
            case 'start-ip':
            case 'fqdn':
            case 'wildcard-fqdn':
            case 'country':
                this.objParam['param1'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            case 'end-ip':
                this.objParam['param2'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            case 'comment':
                this.objParam['comment'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            }
        }
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall address6'
*
* @extends FirewallAddress
*
*/
class FirewallAddress6 extends FirewallAddress {
    /**
    * This method initializes the parameter object for FirewallAddress6 class.
    *
    * @param {string} strEditName - Name or ID entered in 'edit' command.
    *
    */
    begin(strEditName) {
        super.begin(strEditName);
        this.objParam['type'] = 'ipprefix';
        this.objParam['param1'] = '';
        this.objParam['param2'] = '';
        this.objParam['comment'] = '';
    }

    /**
    * This method normalizes the parameter object for FirewallAddress6 class
    * and saves it into g_Domain_Data.
    *
    */
    end() {
        if (this.objParam['type'] === 'iprange') {
            if (this.objParam['param1'] === '') {
                this.objParam['param1'] = '::';
            }
            if (this.objParam['param2'] === '') {
                this.objParam['param2'] = '::';
            }
        } else if (this.objParam['type'] === 'ipprefix') {
            if (this.objParam['param1'] === '') {
                this.objParam['param1'] = '::/0';
            }
        }
        g_Domain_Data[this.strDomainName].address6[this.strEditName] = normalizeFirewallIPv6Address(this.objParam);
    }

    /**
    * This method sets the parameter of the 'firewall address6' object to this
    * class's parameter object.
    *
    * @param {string} strLine - Line of the configuration.
    * @param {Array} arrayToken - Array of the line's tokens.
    *
    */
    set(strLine, arrayToken) {
        if (arrayToken[2]) {
            const intIndexOfParamValue = arrayToken[0].length + arrayToken[1].length + 2;

            switch (arrayToken[1]) {
            case 'type':
                this.objParam['type'] = arrayToken[2];
                break;
            case 'ip6':
            case 'start-ip':
            case 'fqdn':
                this.objParam['param1'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            case 'end-ip':
                this.objParam['param2'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            case 'comment':
                this.objParam['comment'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            }
        }
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for following
* configurations.
*
*   'config firewall addrgrp'
*   'config firewall addrgrp6'
*
* @extends ConfigEdit
*
*/
class FirewallAddrgrp extends ConfigEdit {
    /**
    * This method initializes the parameter object for FirewallAddrgrp class.
    *
    * @param {string} strEditName - Name or ID entered in 'edit' command.
    *
    */
    begin(strEditName) {
        super.begin(strEditName);
        this.objParam['member'] = '';
        this.objParam['comment'] = '';
    }

    /**
    * This method sets the parameter of the firewall address group object to
    * this class's parameter object.
    *
    * @param {string} strLine - Line of the configuration.
    * @param {Array} arrayToken - Array of the line's tokens.
    *
    */
    set(strLine, arrayToken) {
        if (arrayToken[2]) {
            const intIndexOfParamValue = arrayToken[0].length + arrayToken[1].length + 2;

            switch (arrayToken[1]) {
            case 'member':
                this.objParam['member'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            case 'comment':
                this.objParam['comment'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            }
        }
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall addrgrp'
*
* @extends FirewallAddrgrp
*
*/
class FirewallAddrgrp4 extends FirewallAddrgrp {
    /**
    * This method normalizes the parameter object for FirewallAddrgrp4 class
    * and saves it into g_Domain_Data.
    *
    */
    end() {
        g_Domain_Data[this.strDomainName].addrgrp4[this.strEditName] = normalizeFirewallAddressGroup(this.objParam, g_Domain_Data[this.strDomainName].address4, g_Domain_Data[this.strDomainName].addrgrp4);
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall addrgrp6'
*
* @extends FirewallAddrgrp
*
*/
class FirewallAddrgrp6 extends FirewallAddrgrp {
    /**
    * This method normalizes the parameter object for FirewallAddrgrp6 class
    * and saves it into g_Domain_Data.
    *
    */
    end() {
        g_Domain_Data[this.strDomainName].addrgrp6[this.strEditName] = normalizeFirewallAddressGroup(this.objParam, g_Domain_Data[this.strDomainName].address6, g_Domain_Data[this.strDomainName].addrgrp6);
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for following
* configurations.
*
*   'config firewall multicast-address'
*   'config firewall multicast-address6'
*
* @extends ConfigEdit
*
*/
class FirewallMulticastAddress extends ConfigEdit {
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall multicast-address'
*
* @extends FirewallMulticastAddress
*
*/
class FirewallMulticastAddress4 extends FirewallMulticastAddress {
    /**
    * This method initializes the parameter object for
    * FirewallMulticastAddress4 class.
    *
    * @param {string} strEditName - Name or ID entered in 'edit' command.
    *
    */
    begin(strEditName) {
        super.begin(strEditName);
        this.objParam['type'] = 'multicastrange';
        this.objParam['param1'] = '';
        this.objParam['param2'] = '';
        this.objParam['comment'] = '';
    }

    /**
    * This method normalizes the parameter object for
    * FirewallMulticastAddress4 class and saves it into g_Domain_Data.
    *
    */
    end() {
        if (this.objParam['type'] === 'multicastrange') {
            if (this.objParam['param1'] === '') {
                this.objParam['param1'] = '0.0.0.0';
            }
            if (this.objParam['param2'] === '') {
                this.objParam['param2'] = '0.0.0.0';
            }
        }
        g_Domain_Data[this.strDomainName].multicastaddress4[this.strEditName] = normalizeFirewallIPv4MulticastAddress(this.objParam);
    }

    /**
    * This method sets the parameter of the 'firewall multicast-address'
    * object to this class's parameter object.
    *
    * @param {string} strLine - Line of the configuration.
    * @param {Array} arrayToken - Array of the line's tokens.
    *
    */
    set(strLine, arrayToken) {
        if (arrayToken[2]) {
            const intIndexOfParamValue = arrayToken[0].length + arrayToken[1].length + 2;

            switch (arrayToken[1]) {
            case 'type':
                this.objParam['type'] = arrayToken[2];
                break;
            case 'subnet':
                this.objParam['param1'] = arrayToken[2];
                this.objParam['param2'] = arrayToken[3] ? arrayToken[3] : '255.255.255.255';
                break;
            case 'start-ip':
                this.objParam['param1'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            case 'end-ip':
                this.objParam['param2'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            case 'comment':
                this.objParam['comment'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            }
        }
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall multicast-address6'
*
* @extends FirewallMulticastAddress
*
*/
class FirewallMulticastAddress6 extends FirewallMulticastAddress {
    /**
    * This method initializes the parameter object for
    * FirewallMulticastAddress6 class.
    *
    * @param {string} strEditName - Name or ID entered in 'edit' command.
    *
    */
    begin(strEditName) {
        super.begin(strEditName);
        this.objParam['param1'] = '';
        this.objParam['comment'] = '';
    }

    /**
    * This method normalizes the parameter object for
    * FirewallMulticastAddress6 class and saves it into g_Domain_Data.
    *
    */
    end() {
        if (this.objParam['param1'] === '') {
            this.objParam['param1'] = '::/0';
        }
        g_Domain_Data[this.strDomainName].multicastaddress6[this.strEditName] = normalizeFirewallIPv6MulticastAddress(this.objParam);
    }

    /**
    * This method sets the parameter of the 'firewall multicast-address6'
    * object to this class's parameter object.
    *
    * @param {string} strLine - Line of the configuration.
    * @param {Array} arrayToken - Array of the line's tokens.
    *
    */
    set(strLine, arrayToken) {
        if (arrayToken[2]) {
            const intIndexOfParamValue = arrayToken[0].length + arrayToken[1].length + 2;

            switch (arrayToken[1]) {
            case 'ip6':
                this.objParam['param1'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            case 'comment':
                this.objParam['comment'] = strLine.substring(intIndexOfParamValue).trimString('"').trimString('\'');
                break;
            }
        }
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for following
* configurations.
*
*   'config firewall policy'
*   'config firewall policy6'
*   'config firewall policy64'
*   'config firewall policy46'
*
* @extends ConfigEdit
*
*/
class FirewallPolicy extends ConfigEdit {
    /**
    * This constructor defines variables for FirewallPolicy class.
    *
    */
    constructor() {
        super();
        this.intOrderNumber = 0;
    }

    /**
    * This method initializes FirewallPolicy class.
    *
    */
    init() {
        this.intOrderNumber = 0;
    }

    /**
    * This method initializes the parameter object for FirewallPolicy class.
    *
    * @param {string} strEditName - Name or ID entered in 'edit' command.
    *
    */
    begin(strEditName) {
        super.begin(strEditName);
        this.objParam['srcintf'] = '';
        this.objParam['dstintf'] = '';
        this.objParam['srcaddr'] = '';
        this.objParam['dstaddr'] = '';
        this.objParam['schedule'] = '';
        this.objParam['service'] = '';
        this.objParam['srcaddr_negate'] = '';
        this.objParam['dstaddr_negate'] = '';
        this.objParam['service_negate'] = '';
        this.objParam['name'] = '';
        this.objParam['action'] = '';
        this.objParam['status'] = '';
        this.objParam['comments'] = '';
        ++this.intOrderNumber;
    }

    /**
    * This method sets the parameter of the firewall policy object to this
    * class's parameter object.
    *
    * @param {string} strLine - Line of the configuration.
    * @param {Array} arrayToken - Array of the line's tokens.
    *
    */
    set(strLine, arrayToken) {
        if (arrayToken[2]) {
            const intIndexOfParamValue = arrayToken[0].length + arrayToken[1].length + 2;
            const strProperty = arrayToken[1].replaceAll('-', '_');

            switch (arrayToken[1]) {
            case 'srcintf':  // required.
            case 'dstintf':  // required.
            case 'srcaddr':  // required.
            case 'dstaddr':  // required.
            case 'schedule': // required.
            case 'service':
            case 'srcaddr-negate':
            case 'dstaddr-negate':
            case 'service-negate':
            case 'name':
            case 'action':
            case 'status':
            case 'comments':
                this.objParam[strProperty] = strLine.substring(intIndexOfParamValue);
                break;
            }
        }
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall policy'
*
* @extends FirewallPolicy
*
*/
class FirewallPolicy4to4 extends FirewallPolicy {
    /**
    * This method normalizes the parameter object for FirewallPolicy4to4 class
    * and saves it into g_Domain_Data.
    *
    */
    end() {
        this.objParam['srcaddr_negate'] = this.objParam['srcaddr_negate'] === 'enable' ? 'true' : 'false';
        this.objParam['dstaddr_negate'] = this.objParam['dstaddr_negate'] === 'enable' ? 'true' : 'false';
        this.objParam['service_negate'] = this.objParam['service_negate'] === 'enable' ? 'true' : 'false';
        g_Domain_Data[this.strDomainName].policy4to4.push(...normalizeFirewallPolicy(this.strDomainName, '4to4', this.strEditName, this.intOrderNumber, this.objParam));
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall policy6'
*
* @extends FirewallPolicy
*
*/
class FirewallPolicy6to6 extends FirewallPolicy {
    /**
    * This method normalizes the parameter object for FirewallPolicy6to6 class
    * and saves it into g_Domain_Data.
    *
    */
    end() {
        this.objParam['srcaddr_negate'] = this.objParam['srcaddr_negate'] === 'enable' ? 'true' : 'false';
        this.objParam['dstaddr_negate'] = this.objParam['dstaddr_negate'] === 'enable' ? 'true' : 'false';
        this.objParam['service_negate'] = this.objParam['service_negate'] === 'enable' ? 'true' : 'false';
        g_Domain_Data[this.strDomainName].policy6to6.push(...normalizeFirewallPolicy(this.strDomainName, '6to6', this.strEditName, this.intOrderNumber, this.objParam));
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall policy64'
*
* @extends FirewallPolicy
*
*/
class FirewallPolicy6to4 extends FirewallPolicy {
    /**
    * This method normalizes the parameter object for FirewallPolicy6to4 class
    * and saves it into g_Domain_Data.
    *
    */
    end() {
        this.objParam['name'] = '-';
        this.objParam['srcaddr_negate'] = '-';
        this.objParam['dstaddr_negate'] = '-';
        this.objParam['service_negate'] = '-';
        g_Domain_Data[this.strDomainName].policy6to4.push(...normalizeFirewallPolicy(this.strDomainName, '6to4', this.strEditName, this.intOrderNumber, this.objParam));
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall policy46'
*
* @extends FirewallPolicy
*
*/
class FirewallPolicy4to6 extends FirewallPolicy {
    /**
    * This method normalizes the parameter object for FirewallPolicy4to6 class
    * and saves it into g_Domain_Data.
    *
    */
    end() {
        this.objParam['name'] = '-';
        this.objParam['srcaddr_negate'] = '-';
        this.objParam['dstaddr_negate'] = '-';
        this.objParam['service_negate'] = '-';
        g_Domain_Data[this.strDomainName].policy4to6.push(...normalizeFirewallPolicy(this.strDomainName, '4to6', this.strEditName, this.intOrderNumber, this.objParam));
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for following
* configurations.
*
*   'config firewall multicast-policy'
*   'config firewall multicast-policy6'
*
* @extends ConfigEdit
*
*/
class FirewallMulticastPolicy extends ConfigEdit {
    /**
    * This constructor defines variables for FirewallMulticastPolicy class.
    *
    */
    constructor() {
        super();
        this.intOrderNumber = 0;
    }

    /**
    * This method initializes FirewallMulticastPolicy class.
    *
    */
    init() {
        this.intOrderNumber = 0;
    }

    /**
    * This method initializes the parameter object for FirewallMulticastPolicy
    * class.
    *
    * @param {string} strEditName - Name or ID entered in 'edit' command.
    *
    */
    begin(strEditName) {
        super.begin(strEditName);
        this.objParam['srcintf'] = '';
        this.objParam['dstintf'] = '';
        this.objParam['srcaddr'] = '';
        this.objParam['dstaddr'] = '';
        this.objParam['protocol'] = '';
        this.objParam['action'] = '';
        this.objParam['status'] = '';
        this.objParam['start-port'] = '';
        this.objParam['end-port'] = '';
        ++this.intOrderNumber;
    }

    /**
    * This method sets the parameter of the firewall multicast policy object
    * to this class's parameter object.
    *
    * @param {string} strLine - Line of the configuration.
    * @param {Array} arrayToken - Array of the line's tokens.
    *
    */
    set(strLine, arrayToken) {
        if (arrayToken[2]) {
            const intIndexOfParamValue = arrayToken[0].length + arrayToken[1].length + 2;
            const strProperty = arrayToken[1].replaceAll('-', '_');

            switch (arrayToken[1]) {
            case 'srcintf':  // required.
            case 'dstintf':  // required.
            case 'srcaddr':  // required.
            case 'dstaddr':  // required.
            case 'protocol':
            case 'action':
            case 'status':
            case 'start-port':
            case 'end-port':
                this.objParam[strProperty] = strLine.substring(intIndexOfParamValue);
                break;
            }
        }
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall multicast-policy'
*
* @extends FirewallMulticastPolicy
*
*/
class FirewallMulticastPolicy4to4 extends FirewallMulticastPolicy {
    /**
    * This method normalizes the parameter object for
    * FirewallMulticastPolicy4to4 class and saves it into g_Domain_Data.
    *
    */
    end() {
        g_Domain_Data[this.strDomainName].policy4to4m.push(...normalizeFirewallMulticastPolicy(this.strDomainName, '4to4m', this.strEditName, this.intOrderNumber, this.objParam));
    }
}

/**
* This class defines 'edit', 'set', and 'next' commands' actions for the
* following configuration.
*
*   'config firewall multicast-policy6'
*
* @extends FirewallMulticastPolicy
*
*/
class FirewallMulticastPolicy6to6 extends FirewallMulticastPolicy {
    /**
    * This method normalizes the parameter object for
    * FirewallMulticastPolicy6to6 class and saves it into g_Domain_Data.
    *
    */
    end() {
        g_Domain_Data[this.strDomainName].policy6to6m.push(...normalizeFirewallMulticastPolicy(this.strDomainName, '6to6m', this.strEditName, this.intOrderNumber, this.objParam));
    }
}

/*
* ============================================================================
* ============================================================================
*/

/*
* Object to save FortiGate configuration parsed data.
*
* @const {Object}
*/
let g_Domain_Data = {};

/*
* Objects of FortiGate firewall configurations.
*
*/
const editFirewallAddress4            = new FirewallAddress4;
const editFirewallAddress6            = new FirewallAddress6;
const editFirewallAddrgrp4            = new FirewallAddrgrp4;
const editFirewallAddrgrp6            = new FirewallAddrgrp6;
const editFirewallMulticastAddress4   = new FirewallMulticastAddress4;
const editFirewallMulticastAddress6   = new FirewallMulticastAddress6;
const editFirewallServiceCustom       = new FirewallServiceCustom;
const editFirewallServiceGroup        = new FirewallServiceGroup;
const editFirewallPolicy4to4          = new FirewallPolicy4to4;
const editFirewallPolicy4to6          = new FirewallPolicy4to6;
const editFirewallPolicy6to4          = new FirewallPolicy6to4;
const editFirewallPolicy6to6          = new FirewallPolicy6to6;
const editFirewallMulticastPolicy4to4 = new FirewallMulticastPolicy4to4;
const editFirewallMulticastPolicy6to6 = new FirewallMulticastPolicy6to6;

/**
* FortiGate firewall object table.
*
* @const {Object}
*/
const t_FortiGateFirewallObject = {
    'address'           : editFirewallAddress4,
    'address6'          : editFirewallAddress6,
    'addrgrp'           : editFirewallAddrgrp4,
    'addrgrp6'          : editFirewallAddrgrp6,
    'multicast-address' : editFirewallMulticastAddress4,
    'multicast-address6': editFirewallMulticastAddress6,
    'service_custom'    : editFirewallServiceCustom,
    'service_group'     : editFirewallServiceGroup,
    'policy'            : editFirewallPolicy4to4,
    'policy46'          : editFirewallPolicy4to6,
    'policy6'           : editFirewallPolicy6to6,
    'policy64'          : editFirewallPolicy6to4,
    'multicast-policy'  : editFirewallMulticastPolicy4to4,
    'multicast-policy6' : editFirewallMulticastPolicy6to6,
};

/**
* Policy property name table of g_Domain_Data.
*
* @const {Array}
*/
const t_PolicyPropertyName = [
    'policy4to4',
    'policy6to6',
    'policy6to4',
    'policy4to6',
    'policy4to4m',
    'policy6to6m',
];

/**
* List of FortiGate policy types.
*
* @const {Array}
*/
const t_FortiGatePolicyType = {
    '4to4' : POLICY_TYPE_4TO4,
    '6to6' : POLICY_TYPE_6TO6,
    '6to4' : POLICY_TYPE_6TO4,
    '4to6' : POLICY_TYPE_4TO6,
    '4to4m': POLICY_TYPE_4TO4M,
    '6to6m': POLICY_TYPE_6TO6M,
};

/*
* ============================================================================
* General functions for FortiGate configuration
* ============================================================================
*/

/**
* This function returns true if the parameter is ip protocol string.
* Otherwise, it is false.
*
* @param {string} str
* @return {boolean}
*   true if the parameter is ip protocol string.
*   Otherwise, it is false.
*
*/
function isIpProtocol(str) {
    return (str === 'ip');
}

/**
* This function returns true if the parameter is icmp protocol string.
* Otherwise, it is false.
*
* @param {string} str
* @return {boolean}
*   true if the parameter is icmp protocol string.
*   Otherwise, it is false.
*
*/
function isIcmpProtocol(str) {
    return (str === '1');
}

/**
* This function returns true if the parameter is icmp6 protocol string.
* Otherwise, it is false.
*
* @param {string} str
* @return {boolean}
*   true if the parameter is icmp6 protocol string.
*   Otherwise, it is false.
*
*/
function isIcmp6Protocol(str) {
    return (str === '58');
}

/**
* This function returns true if the parameter is tcp protocol string.
* Otherwise, it is false.
*
* @param {string} str
* @return {boolean}
*   true if the parameter is tcp protocol string.
*   Otherwise, it is false.
*
*/
function isTcpProtocol(str) {
    return (str === '6');
}

/**
* This function returns true if the parameter is udp protocol string.
* Otherwise, it is false.
*
* @param {string} str
* @return {boolean}
*   true if the parameter is udp protocol string.
*   Otherwise, it is false.
*
*/
function isUdpProtocol(str) {
    return (str === '17');
}

/**
* This function returns true if the parameter is sctp protocol string.
* Otherwise, it is false.
*
* @param {string} str
* @return {boolean}
*   true if the parameter is sctp protocol string.
*   Otherwise, it is false.
*
*/
function isSctpProtocol(str) {
    return (str === '132');
}

/**
* This function returns the protocol type bit of protocol string.
*
* @param {string} strProtocol
* @return {number} Protocol type bit.
*
* @example
*   strProtocol    Return
*   ---------------------------------------------
*   'ip'        -> PROTOCOL_TYPE_BIT_IP
*   '89'        -> PROTOCOL_TYPE_BIT_IP
*   '1'         -> PROTOCOL_TYPE_BIT_ICMP_ICMP6
*   '58'        -> PROTOCOL_TYPE_BIT_ICMP_ICMP6
*   '6'         -> PROTOCOL_TYPE_BIT_TCP_UDP_SCTP
*   '17'        -> PROTOCOL_TYPE_BIT_TCP_UDP_SCTP
*   '132'       -> PROTOCOL_TYPE_BIT_TCP_UDP_SCTP
*   'undefined' -> PROTOCOL_TYPE_BIT_NONE
*   'UNKNOWN'   -> PROTOCOL_TYPE_BIT_UNSUPPORTED
*/
function getProtocolTypeBit(strProtocol) {
    let intProtocolTypeBit = PROTOCOL_TYPE_BIT_NONE;
    if (isIcmpProtocol(strProtocol)) {
        intProtocolTypeBit |= PROTOCOL_TYPE_BIT_ICMP_ICMP6;
    } else if (isIcmp6Protocol(strProtocol)) {
        intProtocolTypeBit |= PROTOCOL_TYPE_BIT_ICMP_ICMP6;
    } else if (isTcpProtocol(strProtocol)) {
        intProtocolTypeBit |= PROTOCOL_TYPE_BIT_TCP_UDP_SCTP;
    } else if (isUdpProtocol(strProtocol)) {
        intProtocolTypeBit |= PROTOCOL_TYPE_BIT_TCP_UDP_SCTP;
    } else if (isSctpProtocol(strProtocol)) {
        intProtocolTypeBit |= PROTOCOL_TYPE_BIT_TCP_UDP_SCTP;
    } else if (isIpProtocol(strProtocol)) {
        intProtocolTypeBit |= PROTOCOL_TYPE_BIT_IP;
    } else if (Number.isInteger(+strProtocol)) {
        intProtocolTypeBit |= PROTOCOL_TYPE_BIT_IP;
    } else if (strProtocol === 'undefined') {
        // PROTOCOL_TYPE_BIT_NONE
    } else {
        intProtocolTypeBit |= PROTOCOL_TYPE_BIT_UNSUPPORTED;
    }
    return intProtocolTypeBit;
}

/**
* This function returns the protocol type bit of the array of service port
* condition strings.
*
* @param {Array} arrayServicePortCondition
* @return {number} Protocol type bit.
*
* @example
*   arrayServicePortCondition                                                Return
*   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   ['ip;-','89;-'                                                      ] -> PROTOCOL_TYPE_BIT_IP
*   ['ip;-','1/any/any;-'                                               ] -> PROTOCOL_TYPE_BIT_IP|PROTOCOL_TYPE_BIT_ICMP_ICMP6
*   ['ip;-','1/any/any;-','6/eq/any/eq/80;192.168.0.1-192.168.0.100'    ] -> PROTOCOL_TYPE_BIT_IP|PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_TCP_UDP_SCTP
*   ['ip;-','1/any/any;-','6/eq/any/eq/80;all','UNKNOWN;UNKNOWN'        ] -> PROTOCOL_TYPE_BIT_IP|PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_TCP_UDP_SCTP|PROTOCOL_TYPE_BIT_UNSUPPORTED
*/
function getProtocolTypeBitsOfArray(arrayServicePortCondition) {
    let intProtocolTypeBits = PROTOCOL_TYPE_BIT_NONE;
    for (let i=0; i<arrayServicePortCondition.length; ++i) {
        let array = arrayServicePortCondition[i].split(';');
        array = array[0].split('/');
        intProtocolTypeBits |= getProtocolTypeBit(array[0]);
    }
    return intProtocolTypeBits;
}

/*
* ============================================================================
* IP address functions
* ============================================================================
*/

/**
* This function converts IPv4 netmask string to IPv4 prefix length.
*
* @param {string} strIPv4NetMask
* @return {number} IPv4 prefix length.
*
* @example
*   strIPv4NetMask     Return
*   -------------------------
*   '255.255.255.0' -> 24
*/
function getPrefixLengthFromIPv4NetMask(strIPv4NetMask) {
    const arrayStrMaskOctet = strIPv4NetMask.split('.');
    const arrayBytMaskOctet = new Uint8Array([parseInt(arrayStrMaskOctet[0]), parseInt(arrayStrMaskOctet[1]), parseInt(arrayStrMaskOctet[2]), parseInt(arrayStrMaskOctet[3])]);

    let intPrefixLength = 0;
    for (let i=0; i<=3; ++i) {
        let bytMask = arrayBytMaskOctet[i];
        for (let j=7; j>=0; --j) {
            if (bytMask >= Math.pow(2, j)) {
                ++intPrefixLength;
                bytMask -= Math.pow(2, j);
            } else if (bytMask == 0) {
                break;
            }
        }
    }
    return intPrefixLength;
}

/**
* This function converts IPv4 address string with netmask string to CIDR
* format.
*
* @param {string} strIPv4Addr
* @param {string} strIPv4NetMask
* @return {string} CIDR format IPv4 address.
*
* @example
*   strIPv4Addr   strIPv4NetMask     Return
*   -------------------------------------------------
*   '192.168.0.1' '255.255.255.0' -> '192.168.0.1/24'
*/
function getIPv4AddrWithPrefixLength(strIPv4Addr, strIPv4NetMask) {
    return (strIPv4Addr + '/' + getPrefixLengthFromIPv4NetMask(strIPv4NetMask));
}

/**
* This function converts octet's prefix length to octet's netmask.
*
* @param {number} intOctetPrefixLength
* @return {number} Octet's netmask.
*
* @example
*   intOctetPrefixLength    Return
*   ------------------------------
*   0                    ->   0
*   1                    -> 128
*   2                    -> 192
*   3                    -> 224
*   4                    -> 240
*   5                    -> 248
*   6                    -> 252
*   7                    -> 254
*   8                    -> 255
*/
function getOctetNetMaskFromOctetPrefixLength(intOctetPrefixLength) {
    return (256 - Math.pow(2, 8 - intOctetPrefixLength));
}

/**
* This function converts IPv4 prefix length to IPv4 netmask string.
*
* @param {number} intIPv4PrefixLength
* @return {string} IPv4 netmask string.
*
* @example
*   intIPv4PrefixLength    Return
*   ----------------------------------------
*    0                  -> '0.0.0.0'
*    8                  -> '255.0.0.0'
*   16                  -> '255.255.0.0'
*   20                  -> '255.255.240.0'
*   24                  -> '255.255.255.0'
*   28                  -> '255.255.255.240'
*   30                  -> '255.255.255.252'
*   32                  -> '255.255.255.255'
*/
function getIPv4NetMaskFromPrefixLength(intIPv4PrefixLength) {
    const arrayBytMaskOctet = new Uint8Array(4);

    if (intIPv4PrefixLength < 8) {
        arrayBytMaskOctet[0] = getOctetNetMaskFromOctetPrefixLength(intIPv4PrefixLength);
        arrayBytMaskOctet[1] = 0;
        arrayBytMaskOctet[2] = 0;
        arrayBytMaskOctet[3] = 0;
    } else if (intIPv4PrefixLength < 16) {
        arrayBytMaskOctet[0] = 255;
        arrayBytMaskOctet[1] = getOctetNetMaskFromOctetPrefixLength(intIPv4PrefixLength - 8);
        arrayBytMaskOctet[2] = 0;
        arrayBytMaskOctet[3] = 0;
    } else if (intIPv4PrefixLength < 24) {
        arrayBytMaskOctet[0] = 255;
        arrayBytMaskOctet[1] = 255;
        arrayBytMaskOctet[2] = getOctetNetMaskFromOctetPrefixLength(intIPv4PrefixLength - 16);
        arrayBytMaskOctet[3] = 0;
    } else {
        arrayBytMaskOctet[0] = 255;
        arrayBytMaskOctet[1] = 255;
        arrayBytMaskOctet[2] = 255;
        arrayBytMaskOctet[3] = getOctetNetMaskFromOctetPrefixLength(intIPv4PrefixLength - 24);
    }
    return (arrayBytMaskOctet[0].toString() + '.' + arrayBytMaskOctet[1].toString() + '.' + arrayBytMaskOctet[2].toString() + '.' + arrayBytMaskOctet[3].toString());
}

/**
* This function converts IPv6 prefix length to IPv6 netmask string.
*
* @param {number} intIPv6PrefixLength
* @return {string} IPv6 netmask string.
*
* @example
*   intIPv6PrefixLength    Return
*   ----------------------------------------------------------------
*     0                 -> '0000:0000:0000:0000:0000:0000:0000:0000'
*    16                 -> 'ffff:0000:0000:0000:0000:0000:0000:0000'
*    32                 -> 'ffff:ffff:0000:0000:0000:0000:0000:0000'
*    64                 -> 'ffff:ffff:ffff:ffff:0000:0000:0000:0000'
*    96                 -> 'ffff:ffff:ffff:ffff:ffff:ffff:0000:0000'
*   128                 -> 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
*/
function getIPv6NetMaskFromPrefixLength(intIPv6PrefixLength) {
    const arrayBytMaskOctet = new Uint8Array(16);
    const intIndexToCalc = Math.trunc(intIPv6PrefixLength / 8);
    for (let i=0; i<=intIndexToCalc-1; ++i) {
        arrayBytMaskOctet[i] = 255;
    }
    if (intIndexToCalc < 16) {
        arrayBytMaskOctet[intIndexToCalc] = getOctetNetMaskFromOctetPrefixLength(intIPv6PrefixLength - Math.trunc(intIPv6PrefixLength / 8) * 8);
        for (let i=intIndexToCalc+1; i<16; ++i) {
            arrayBytMaskOctet[i] = 0;
        }
    }

    let strNetMask = '';
    strNetMask += ('0' + arrayBytMaskOctet[0].toString(16)).slice(-2);
    strNetMask += ('0' + arrayBytMaskOctet[1].toString(16)).slice(-2);
    for (let i=2; i<16;) {
        strNetMask += ':';
        strNetMask += ('0' + arrayBytMaskOctet[i++].toString(16)).slice(-2);
        strNetMask += ('0' + arrayBytMaskOctet[i++].toString(16)).slice(-2);
    }
    return strNetMask;
}

/**
* This function returns the start address (i.e., network address) of the
* segment of the specified IPv4 address.
*
* @param {string} strIPv4Addr
* @param {string} strIPv4NetMask
* @return {string} Start address of the segment.
*
* @example
*   strIPv4Addr   strIPv4NetMask     Return
*   ----------------------------------------------
*   '192.168.0.1' '255.255.255.0' -> '192.168.0.0'
*/
function getIPv4StartAddr(strIPv4Addr, strIPv4NetMask) {
    return getBitwiseANDedIPv4Addr(strIPv4Addr, strIPv4NetMask);
}

/**
* This function returns the end address (i.e., broadcast address) of the
* segment of the specified IPv4 address.
*
* @param {string} strIPv4Addr
* @param {string} strIPv4NetMask
* @return {string} End address of the segment.
*
* @example
*   strIPv4Addr   strIPv4NetMask     Return
*   ------------------------------------------------
*   '192.168.0.1' '255.255.255.0' -> '192.168.0.255'
*/
function getIPv4EndAddr(strIPv4Addr, strIPv4NetMask) {
    return getBitwiseORedIPv4AddrWithInvertBits(strIPv4Addr, strIPv4NetMask);
}

/**
* This function returns the start address (i.e., network address) of
* the segment of the specified IPv6 address.
* IPv4-compatible address and IPv4-mapped address are not supported.
*
* @param {string} strIPv6Addr
* @param {string} strIPv6NetMask
* @return {string} Start address of the segment.
*
* @example
*   strIPv6Addr                               strIPv6NetMask                               Return
*   --------------------------------------------------------------------------------------------------------------------------------
*   '2001:0db8:0001:0002:0003:0004:0005:0006' 'ffff:ffff:ffff:0000:0000:0000:0000:0000' -> '2001:0db8:0001:0000:0000:0000:0000:0000'
*/
function getIPv6StartAddr(strIPv6Addr, strIPv6NetMask) {
    const arrayStrIPv6Hextet = strIPv6Addr.split(':');
    const arrayIntIPv6Hextet = new Uint16Array([
        parseInt(arrayStrIPv6Hextet[0], 16), parseInt(arrayStrIPv6Hextet[1], 16), parseInt(arrayStrIPv6Hextet[2], 16), parseInt(arrayStrIPv6Hextet[3], 16),
        parseInt(arrayStrIPv6Hextet[4], 16), parseInt(arrayStrIPv6Hextet[5], 16), parseInt(arrayStrIPv6Hextet[6], 16), parseInt(arrayStrIPv6Hextet[7], 16)]);
    const arrayStrMaskHextet = strIPv6NetMask.split(':');
    const arrayIntMaskHextet = new Uint16Array([
        parseInt(arrayStrMaskHextet[0], 16), parseInt(arrayStrMaskHextet[1], 16), parseInt(arrayStrMaskHextet[2], 16), parseInt(arrayStrMaskHextet[3], 16),
        parseInt(arrayStrMaskHextet[4], 16), parseInt(arrayStrMaskHextet[5], 16), parseInt(arrayStrMaskHextet[6], 16), parseInt(arrayStrMaskHextet[7], 16)]);

    let intHextet = arrayIntIPv6Hextet[0] & arrayIntMaskHextet[0];
    let strIPv6NetAddr = ('0' + (intHextet >> 8).toString(16)).slice(-2) + ('0' + (intHextet & 0xFF).toString(16)).slice(-2);
    for (let i=1; i<8; ++i) {
        intHextet = arrayIntIPv6Hextet[i] & arrayIntMaskHextet[i];
        strIPv6NetAddr += ':' + ('0' + (intHextet >> 8).toString(16)).slice(-2) + ('0' + (intHextet & 0xFF).toString(16)).slice(-2);
    }
    return strIPv6NetAddr;
}

/**
* This function returns the end address of the segment of the specified IPv6
* address.
* IPv4-compatible address and IPv4-mapped address are not supported.
*
* @param {string} strIPv6Addr
* @param {string} strIPv6NetMask
* @return {string} End address of the segment.
*
* @example
*   strIPv6Addr                               strIPv6NetMask                               Return
*   --------------------------------------------------------------------------------------------------------------------------------
*   '2001:0db8:0001:0002:0003:0004:0005:0006' 'ffff:ffff:ffff:0000:0000:0000:0000:0000' -> '2001:0db8:0001:ffff:ffff:ffff:ffff:ffff'
*/
function getIPv6EndAddr(strIPv6Addr, strIPv6NetMask) {
    const arrayStrIPv6Hextet = strIPv6Addr.split(':');
    const arrayIntIPv6Hextet = new Uint16Array([
        parseInt(arrayStrIPv6Hextet[0], 16), parseInt(arrayStrIPv6Hextet[1], 16), parseInt(arrayStrIPv6Hextet[2], 16), parseInt(arrayStrIPv6Hextet[3], 16),
        parseInt(arrayStrIPv6Hextet[4], 16), parseInt(arrayStrIPv6Hextet[5], 16), parseInt(arrayStrIPv6Hextet[6], 16), parseInt(arrayStrIPv6Hextet[7], 16)]);
    const arrayStrMaskHextet = strIPv6NetMask.split(':');
    const arrayIntMaskHextet = new Uint16Array([
        parseInt(arrayStrMaskHextet[0], 16), parseInt(arrayStrMaskHextet[1], 16), parseInt(arrayStrMaskHextet[2], 16), parseInt(arrayStrMaskHextet[3], 16),
        parseInt(arrayStrMaskHextet[4], 16), parseInt(arrayStrMaskHextet[5], 16), parseInt(arrayStrMaskHextet[6], 16), parseInt(arrayStrMaskHextet[7], 16)]);

    let intHextet = arrayIntIPv6Hextet[0] | (arrayIntMaskHextet[0] ^ 0xFFFF);
    let strIPv6LastAddr = ('0' + (intHextet >> 8).toString(16)).slice(-2) + ('0' + (intHextet & 0xFF).toString(16)).slice(-2);
    for (let i=1; i<8; ++i) {
        intHextet = arrayIntIPv6Hextet[i] | (arrayIntMaskHextet[i] ^ 0xFFFF);
        strIPv6LastAddr += ':' + ('0' + (intHextet >> 8).toString(16)).slice(-2) + ('0' + (intHextet & 0xFF).toString(16)).slice(-2);
    }
    return strIPv6LastAddr;
}

/**
* This function converts IPv4 address string to the array of hextet string and
* returns its array.
*
* @param {string} strOctetsIncludePeriod
* @return {(Array|undefined)} Array of hextet string of a IPv4 address string.
*
* @example
*   strOctetsIncludePeriod    Return
*   -----------------------------------------
*   '192.168.0.1'          -> ['c0a8','0001']
*   '192.256.0.1'          -> []
*   '192.168.a.1'          -> []
*   'UNKNOWN'              -> undefined
*/
function getHextetStrArrayFromOctetStr(strOctetsIncludePeriod) {
    const arrayStrFullHextet = [];
    const arrayStrOctet = strOctetsIncludePeriod.split('.');
    const arrayIntOctet = new Uint8Array(arrayStrOctet.length);
    for (let i=0; i<arrayStrOctet.length; ++i) {
        if (arrayStrOctet[i].length > 3) {
            return undefined;
        }
        const c1 = arrayStrOctet[i].charAt(0);
        const c2 = arrayStrOctet[i].charAt(1);
        const c3 = arrayStrOctet[i].charAt(2);
        const intOctet = parseInt(arrayStrOctet[i]);
        if ((c1 === '' || (c1 >= '0' && c1 <= '9')) &&
            (c2 === '' || (c2 >= '0' && c2 <= '9')) &&
            (c3 === '' || (c3 >= '0' && c3 <= '9')) &&
            (intOctet <= 255)) {
            arrayIntOctet[i] = intOctet;
        } else {
            return arrayStrFullHextet;
        }
    }
    for (let i=0; i<(arrayIntOctet.length-1); i+=2) {
        arrayStrFullHextet[i/2] = ('0' + arrayIntOctet[i].toString(16)).slice(-2) + ('0' + arrayIntOctet[i+1].toString(16)).slice(-2);
    }
    return arrayStrFullHextet;
}

/**
* This function converts a part of IPv6 address string to the array of hextet
* string and returns its array. The parameter can be less than eight hextets.
*
* @param {string} strHextetsIncludeColon
* @return {(Array|undefined)} Array of hextet string of a part of IPv6 address.
*
* @example
*   strHextetsIncludeColon                       Return
*   ------------------------------------------------------------------------------------------------------
*   '2001:0db8:1234:5678:90aB:cDeF:feDC:bA09' -> ['2001','0db8','1234','5678','90ab','cdef','fedc','ba09']
*   '2001:db8::1'                             -> ['2001','0db8','0000','0000','0000','0000','0000','0001']
*   '2001:db8::gggg'                          -> []
*   '2001:db8::fffff:1'                       -> undefined
*   'UNKNOWN'                                 -> undefined
*/
function getHextetStrArray(strHextetsIncludeColon) {
    const arrayStrFull = [];
    const arrayStrHextet = strHextetsIncludeColon.split(':');
    const arrayIntHextet = new Uint16Array(arrayStrHextet.length);
    for (let i=0; i<arrayStrHextet.length; ++i) {
        if (arrayStrHextet[i].length > 4) {
            return undefined;
        }
        const c1 = arrayStrHextet[i].charAt(0);
        const c2 = arrayStrHextet[i].charAt(1);
        const c3 = arrayStrHextet[i].charAt(2);
        const c4 = arrayStrHextet[i].charAt(3);
        const intHextet = parseInt(arrayStrHextet[i], 16);
        if ((c1 === '' || (c1 >= '0' && c1 <= '9') || (c1 >= 'a' && c1 <= 'f') || (c1 >= 'A' && c1 <= 'F')) &&
            (c2 === '' || (c2 >= '0' && c2 <= '9') || (c2 >= 'a' && c2 <= 'f') || (c2 >= 'A' && c2 <= 'F')) &&
            (c3 === '' || (c3 >= '0' && c3 <= '9') || (c3 >= 'a' && c3 <= 'f') || (c3 >= 'A' && c3 <= 'F')) &&
            (c4 === '' || (c4 >= '0' && c4 <= '9') || (c4 >= 'a' && c4 <= 'f') || (c4 >= 'A' && c4 <= 'F')) &&
            (intHextet <= 65535)) {
            arrayIntHextet[i] = intHextet;
        } else {
            return arrayStrFull;
        }
    }
    for (let i=0; i<arrayStrHextet.length; ++i) {
        arrayStrFull[i] = ('0' + (arrayIntHextet[i] >> 8).toString(16)).slice(-2) + ('0' + (arrayIntHextet[i] & 0xFF).toString(16)).slice(-2);
    }
    return arrayStrFull;
}

/**
* This function converts IPv6 address string to the array of hextet string and
* returns its array.
*
* @param {string} strIPv6Addr
* @return {Array} Array of hextet string of an IPv6 address.
*
* @example
*   strIPv6Addr                                    Return
*   --------------------------------------------------------------------------------------------------------
*   '2001:0db8:1234:5678:90aB:cDeF:feDC:bA09'   -> ['2001','0db8','1234','5678','90ab','cdef','fedc','ba09']
*   '0000:0000:0000:0000:0000:0000:192.168.0.1' -> ['0000','0000','0000','0000','0000','0000','c0a8','0001']
*   '0000:0000:0000:0000:0000:ffff:192.168.0.1' -> ['0000','0000','0000','0000','0000','ffff','c0a8','0001']
*   '2001:db8::1'                               -> ['2001','0db8','0000','0000','0000','0000','0000','0001']
*   '::192.168.0.1'                             -> ['0000','0000','0000','0000','0000','0000','c0a8','0001']
*   '::ffff:192.168.0.1'                        -> ['0000','0000','0000','0000','0000','ffff','c0a8','0001']
*   'eeee:0000:0000:0000:0000:ffff:192.168.0.1' -> []
*   '::eeee:192.168.0.1'                        -> []
*   '2001:db8::fffff:1'                         -> []
*   'UNKNOWN'                                   -> []
*/
function getIPv6HextetStrArray(strIPv6Addr) {
    const arrayStrHextet = [];
    const intIndexOfDblColon = strIPv6Addr.indexOf('::');

    let arrayStrFrontHextet = [];
    let strRear = '';
    if (intIndexOfDblColon == -1) { // Not compressed format.
        arrayStrFrontHextet.length = 0;
        strRear = strIPv6Addr;
    } else { // Compressed format.
        arrayStrFrontHextet = getHextetStrArray(strIPv6Addr.substring(0, intIndexOfDblColon));
        if (arrayStrFrontHextet == undefined) {
            return arrayStrHextet;
        }
        strRear = strIPv6Addr.substring(intIndexOfDblColon+2);
    }

    let arrayStrRearHextet = [];
    const intIndexOfPeriod = strRear.indexOf('.');
    if (intIndexOfPeriod == -1) { // IPv6 standard address.
        arrayStrRearHextet = getHextetStrArray(strRear);
        if (arrayStrRearHextet == undefined) {
            return arrayStrHextet;
        }
    } else { // IPv4-compatible address or IPv4-mapped address.
        const intEndOfHextet = strRear.lastIndexOf(':');
        if (intEndOfHextet == -1) {
            arrayStrRearHextet = getHextetStrArrayFromOctetStr(strRear);
            if (arrayStrRearHextet == undefined) {
                return arrayStrHextet;
            }
        } else {
            const arrayStrEndOfHextet = getHextetStrArray(strRear.substring(0, intEndOfHextet));
            if (arrayStrEndOfHextet == undefined) {
                return arrayStrHextet;
            }
            const arrayStrHextetOfIPv4 = getHextetStrArrayFromOctetStr(strRear.substring(intEndOfHextet+1));
            if (arrayStrHextetOfIPv4 == undefined) {
                return arrayStrHextet;
            }
            arrayStrRearHextet.push(...arrayStrEndOfHextet);
            arrayStrRearHextet.push(...arrayStrHextetOfIPv4);
        }
    }

    if ((intIndexOfDblColon == -1 && arrayStrRearHextet.length == 8) || (intIndexOfDblColon != -1 && (arrayStrFrontHextet.length + arrayStrRearHextet.length) <= 7)) {
        let index = 0;
        for (let i=0; i<arrayStrFrontHextet.length; ++i) {
            arrayStrHextet[index++] = arrayStrFrontHextet[i];
        }
        for (let i=0; i<(8-arrayStrFrontHextet.length-arrayStrRearHextet.length); ++i) {
            arrayStrHextet[index++] = '0000';
        }
        for (let i=0; i<arrayStrRearHextet.length; ++i) {
            arrayStrHextet[index++] = arrayStrRearHextet[i];
        }
        if (intIndexOfPeriod != -1) {
            if (parseInt(arrayStrHextet[0], 16) !== 0 ||
                parseInt(arrayStrHextet[1], 16) !== 0 ||
                parseInt(arrayStrHextet[2], 16) !== 0 ||
                parseInt(arrayStrHextet[3], 16) !== 0 ||
                parseInt(arrayStrHextet[4], 16) !== 0 ||
                (parseInt(arrayStrHextet[5], 16) !== 0 && arrayStrHextet[5] !== 'ffff')) {
                arrayStrHextet.length = 0;
            }
        }
    }
    return arrayStrHextet;
}

/**
* This function adapts the IPv6 address without prefix length to the full
* represented and returns the adapted address. It is '' if the argument is not
* IPv6 address.
*
* @param {string} strIPv6Addr
* @return {string} Full represented IPv6 address without prefix length.
*
* @example
*   strIPv6Addr                                    Return
*   ----------------------------------------------------------------------------------------
*   '2001:0db8:1234:5678:90aB:cDeF:feDC:bA09'   -> '2001:0db8:1234:5678:90ab:cdef:fedc:ba09'
*   '0000:0000:0000:0000:0000:0000:192.168.0.1' -> '0000:0000:0000:0000:0000:0000:c0a8:0001'
*   '0000:0000:0000:0000:0000:ffff:192.168.0.1' -> '0000:0000:0000:0000:0000:ffff:c0a8:0001'
*   '2001:db8::1'                               -> '2001:0db8:0000:0000:0000:0000:0000:0001'
*   '::192.168.0.1'                             -> '0000:0000:0000:0000:0000:0000:c0a8:0001'
*   '::ffff:192.168.0.1'                        -> '0000:0000:0000:0000:0000:ffff:c0a8:0001'
*   'eeee:0000:0000:0000:0000:ffff:192.168.0.1' -> ''
*   '::eeee:192.168.0.1'                        -> ''
*   '2001:db8::fffff:1'                         -> ''
*   'UNKNOWN'                                   -> ''
*/
function getIPv6FullRepresentedAddr(strIPv6Addr) {
    let strNormalizedIPv6Addr = '';
    const array = getIPv6HextetStrArray(strIPv6Addr);
    if (array[0]) {
        strNormalizedIPv6Addr = array[0];
        for (let i=1; i<array.length; ++i) {
            strNormalizedIPv6Addr += ':' + array[i];
        }
    }
    return strNormalizedIPv6Addr;
}

/**
* This function adapts the IPv6 address with prefix length to the full
* represented and returns the adapted address. It is '' if the argument is not
* IPv6 address.
*
* @param {string} strIPv6AddrWithPrefixLength
* @return {string} Full represented IPv6 address with prefix length.
*
* @example
*   strIPv6Addr                                       Return
*   -----------------------------------------------------------------------------------------------
*   '2001:0db8:1234:5678:90aB:cDeF:feDC:bA09/128'  -> '2001:0db8:1234:5678:90ab:cdef:fedc:ba09/128'
*   '0000:0000:0000:0000:0000:0000:192.168.0.1/96' -> '0000:0000:0000:0000:0000:0000:c0a8:0001/96'
*   '0000:0000:0000:0000:0000:ffff:192.168.0.1/96' -> '0000:0000:0000:0000:0000:ffff:c0a8:0001/96'
*   '2001:db8::1/128'                              -> '2001:0db8:0000:0000:0000:0000:0000:0001/128'
*   '::192.168.0.1/96'                             -> '0000:0000:0000:0000:0000:0000:c0a8:0001/96'
*   '::ffff:192.168.0.1/96'                        -> '0000:0000:0000:0000:0000:ffff:c0a8:0001/96'
*   'eeee:0000:0000:0000:0000:ffff:192.168.0.1/96' -> ''
*   '::eeee:192.168.0.1/128'                       -> ''
*   '2001:db8::fffff:1/128'                        -> ''
*   'UNKNOWN'                                      -> ''
*/
function getIPv6FullRepresentedAddrWithPrefixLength(strIPv6AddrWithPrefixLength) {
    const arrayStrIPv6 = strIPv6AddrWithPrefixLength.split('/');
    const strNormalizedIPv6Addr = getIPv6FullRepresentedAddr(arrayStrIPv6[0]);
    if (strNormalizedIPv6Addr === '') {
        return '';
    }
    return (strNormalizedIPv6Addr + '/' + arrayStrIPv6[1]);
}

/**
* This function adapts the IPv6 address without prefix length to the compressed
* represented and returns the adapted address. It is '' if the argument is not
* IPv6 address.
*
* @param {string} strIPv6Addr
* @return {string} Compressed represented IPv6 address without prefix length.
*
* @example
*   strIPv6Addr                                    Return
*   ---------------------------------------------------------------------------------------
*   '0000:0000:0000:0000:0000:0000:0000:0000'   -> '::'
*   '0000:0000:0000:0000:0000:0000:0000:0001'   -> '::1'
*   '2001:0db8:0000:0000:0000:0000:0000:0001'   -> '2001:db8::1'
*   '2001:0db8:1234:5678:90aB:cDeF:feDC:bA09'   -> '2001:db8:1234:5678:90ab:cdef:fedc:ba09'
*   '0000:0000:0000:0000:0000:0000:192.168.0.1' -> '::192.168.0.1'
*   '0000:0000:0000:0000:0000:ffff:192.168.0.1' -> '::ffff:192.168.0.1'
*   '2001:db8::1'                               -> '2001:0db8::1'
*   '::192.168.0.1'                             -> '::192.168.0.1'
*   '::ffff:192.168.0.1'                        -> '::ffff:192.168.0.1'
*   'eeee:0000:0000:0000:0000:ffff:192.168.0.1' -> ''
*   '::eeee:192.168.0.1'                        -> ''
*   '2001:db8::fffff:1'                         -> ''
*   'UNKNOWN'                                   -> ''
*/
function getIPv6CompressedAddr(strIPv6Addr) {
    let strCompressedIPv6Addr = '';
    const array = getIPv6HextetStrArray(strIPv6Addr);
    if (array[0]) {
        for (let i=0; i<array.length; ++i) {
            array[i] = array[i].replace(/^0{1,3}/, '');
        }

        const arrayIPv4 = strIPv6Addr.match(/:(\d+\.\d+\.\d+\.\d+)$/);
        if (arrayIPv4 && arrayIPv4[1]) {
            // Recover IPv4-compatible address and IPv4-mapped address.
            strCompressedIPv6Addr = array.slice(0, 6).join(':') + ':' + arrayIPv4[1];
        } else {
            strCompressedIPv6Addr = array.join(':');
        }

        // Compress.
        strCompressedIPv6Addr = strCompressedIPv6Addr.replace('0:0:0:0:0:0:0:0', '::');
        for (let i=0; i<=10; i+=2) {
            const strTemp = strCompressedIPv6Addr.replace('0:0:0:0:0:0:0'.substring(i), ':');
            if (strCompressedIPv6Addr !== strTemp) {
                strCompressedIPv6Addr = strTemp;
                break;
            }
        }
        strCompressedIPv6Addr = strCompressedIPv6Addr.replace(':::', '::');
    }
    return strCompressedIPv6Addr;
}

/**
* This function adapts the IPv6 address with prefix length to the compressed
* represented and returns the adapted address. It is '' if the argument is not
* IPv6 address.
*
* @param {string} strIPv6AddrWithPrefixLength
* @return {string} Compressed represented IPv6 address with prefix length.
*
* @example
*   strIPv6Addr                                        Return
*   -----------------------------------------------------------------------------------------------
*   '0000:0000:0000:0000:0000:0000:0000:0000/0'     -> '::/0'
*   '0000:0000:0000:0000:0000:0000:0000:0001/128'   -> '::1/128'
*   '2001:0db8:0000:0000:0000:0000:0000:0001/128'   -> '2001:db8::1/128'
*   '2001:0db8:1234:5678:90aB:cDeF:feDC:bA09/128'   -> '2001:db8:1234:5678:90ab:cdef:fedc:ba09/128'
*   '0000:0000:0000:0000:0000:0000:192.168.0.1/128' -> '::192.168.0.1/128'
*   '0000:0000:0000:0000:0000:ffff:192.168.0.1/128' -> '::ffff:192.168.0.1/128'
*   '2001:db8::1/128'                               -> '2001:0db8::1/128'
*   '::192.168.0.1/128'                             -> '::192.168.0.1/128'
*   '::ffff:192.168.0.1/128'                        -> '::ffff:192.168.0.1/128'
*   'eeee:0000:0000:0000:0000:ffff:192.168.0.1/128' -> ''
*   '::eeee:192.168.0.1/128'                        -> ''
*   '2001:db8::fffff:1/128'                         -> ''
*   'UNKNOWN'                                       -> ''
*/
function getIPv6CompressedAddrWithPrefixLength(strIPv6AddrWithPrefixLength) {
    const arrayStrIPv6 = strIPv6AddrWithPrefixLength.split('/');
    const strCompressedIPv6Addr = getIPv6CompressedAddr(arrayStrIPv6[0]);
    if (strCompressedIPv6Addr === '') {
        return '';
    }
    return (strCompressedIPv6Addr + '/' + arrayStrIPv6[1]);
}

/**
* This function returns the address that bitwise ANDed of both addresses.
*
* @param {string} strIPv4AddrA
* @param {string} strIPv4AddrB
* @return {string} Address that bitwise ANDed of both addresses.
*
* @example
*   strIPv4Addr1   strIPv4Addr2       Return
*   ------------------------------------------------
*   '192.168.17.1' '255.255.240.0' -> '192.168.16.0'
*   '192.168.17.1' '0.0.15.255'    -> '0.0.1.1'
*/
function getBitwiseANDedIPv4Addr(strIPv4AddrA, strIPv4AddrB) {
    const arrayStrIPv4AOctet = strIPv4AddrA.split('.');
    const arrayBytIPv4AOctet = new Uint8Array([parseInt(arrayStrIPv4AOctet[0]), parseInt(arrayStrIPv4AOctet[1]), parseInt(arrayStrIPv4AOctet[2]), parseInt(arrayStrIPv4AOctet[3])]);
    const arrayStrIPv4BOctet = strIPv4AddrB.split('.');
    const arrayBytIPv4BOctet = new Uint8Array([parseInt(arrayStrIPv4BOctet[0]), parseInt(arrayStrIPv4BOctet[1]), parseInt(arrayStrIPv4BOctet[2]), parseInt(arrayStrIPv4BOctet[3])]);
    return (
        (arrayBytIPv4AOctet[0] & arrayBytIPv4BOctet[0]).toString() + '.' +
        (arrayBytIPv4AOctet[1] & arrayBytIPv4BOctet[1]).toString() + '.' +
        (arrayBytIPv4AOctet[2] & arrayBytIPv4BOctet[2]).toString() + '.' +
        (arrayBytIPv4AOctet[3] & arrayBytIPv4BOctet[3]).toString());
}

/**
* This function returns the address that bitwise ORed of both addresses.
*
* @param {string} strIPv4AddrA
* @param {string} strIPv4AddrB
* @return {string} Address that bitwise ORed of both addresses.
*
* @example
*   strIPv4Addr1   strIPv4Addr2       Return
*   --------------------------------------------------
*   '192.168.17.1' '255.255.240.0' -> '255.255.241.1'
*   '192.168.17.1' '0.0.15.255'    -> '192.168.31.255'
*/
function getBitwiseORedIPv4Addr(strIPv4AddrA, strIPv4AddrB) {
    const arrayStrIPv4AOctet = strIPv4AddrA.split('.');
    const arrayBytIPv4AOctet = new Uint8Array([parseInt(arrayStrIPv4AOctet[0]), parseInt(arrayStrIPv4AOctet[1]), parseInt(arrayStrIPv4AOctet[2]), parseInt(arrayStrIPv4AOctet[3])]);
    const arrayStrIPv4BOctet = strIPv4AddrB.split('.');
    const arrayBytIPv4BOctet = new Uint8Array([parseInt(arrayStrIPv4BOctet[0]), parseInt(arrayStrIPv4BOctet[1]), parseInt(arrayStrIPv4BOctet[2]), parseInt(arrayStrIPv4BOctet[3])]);
    return (
        (arrayBytIPv4AOctet[0] | arrayBytIPv4BOctet[0]).toString() + '.' +
        (arrayBytIPv4AOctet[1] | arrayBytIPv4BOctet[1]).toString() + '.' +
        (arrayBytIPv4AOctet[2] | arrayBytIPv4BOctet[2]).toString() + '.' +
        (arrayBytIPv4AOctet[3] | arrayBytIPv4BOctet[3]).toString());
}

/**
* This function inverts bitwise the second argument address and returns the
* address that bitwise ANDed the first argument address.
*
* @param {string} strIPv4AddrA
* @param {string} strIPv4AddrB
* @return {string}
*   Address that bitwise ANDed the address A with the address B inverted bits.
*
* @example
*   strIPv4Addr1   strIPv4Addr2       Return
*   ------------------------------------------------
*   '192.168.17.1' '255.255.240.0' -> '0.0.1.1'
*   '192.168.17.1' '0.0.15.255'    -> '192.168.16.0'
*/
function getBitwiseANDedIPv4AddrWithInvertBits(strIPv4AddrA, strIPv4AddrB) {
    const arrayStrIPv4AOctet = strIPv4AddrA.split('.');
    const arrayBytIPv4AOctet = new Uint8Array([parseInt(arrayStrIPv4AOctet[0]), parseInt(arrayStrIPv4AOctet[1]), parseInt(arrayStrIPv4AOctet[2]), parseInt(arrayStrIPv4AOctet[3])]);
    const arrayStrIPv4BOctet = strIPv4AddrB.split('.');
    const arrayBytIPv4BOctet = new Uint8Array([parseInt(arrayStrIPv4BOctet[0]), parseInt(arrayStrIPv4BOctet[1]), parseInt(arrayStrIPv4BOctet[2]), parseInt(arrayStrIPv4BOctet[3])]);
    return (
        (arrayBytIPv4AOctet[0] & (arrayBytIPv4BOctet[0] ^ 0xFF)).toString() + '.' +
        (arrayBytIPv4AOctet[1] & (arrayBytIPv4BOctet[1] ^ 0xFF)).toString() + '.' +
        (arrayBytIPv4AOctet[2] & (arrayBytIPv4BOctet[2] ^ 0xFF)).toString() + '.' +
        (arrayBytIPv4AOctet[3] & (arrayBytIPv4BOctet[3] ^ 0xFF)).toString());
}

/**
* This function inverts bitwise the second argument address and returns the
* address that bitwise ORed the first argument address.
*
* @param {string} strIPv4AddrA
* @param {string} strIPv4AddrB
* @return {string}
*   Address that bitwise ORed the address A with the address B inverted bits.
*
* @example
*   strIPv4Addr1   strIPv4Addr2       Return
*   --------------------------------------------------
*   '192.168.17.1' '255.255.240.0' -> '192.168.31.255'
*   '192.168.17.1' '0.0.15.255'    -> '255.255.241.1'
*/
function getBitwiseORedIPv4AddrWithInvertBits(strIPv4AddrA, strIPv4AddrB) {
    const arrayStrIPv4AOctet = strIPv4AddrA.split('.');
    const arrayBytIPv4AOctet = new Uint8Array([parseInt(arrayStrIPv4AOctet[0]), parseInt(arrayStrIPv4AOctet[1]), parseInt(arrayStrIPv4AOctet[2]), parseInt(arrayStrIPv4AOctet[3])]);
    const arrayStrIPv4BOctet = strIPv4AddrB.split('.');
    const arrayBytIPv4BOctet = new Uint8Array([parseInt(arrayStrIPv4BOctet[0]), parseInt(arrayStrIPv4BOctet[1]), parseInt(arrayStrIPv4BOctet[2]), parseInt(arrayStrIPv4BOctet[3])]);
    return (
        (arrayBytIPv4AOctet[0] | (arrayBytIPv4BOctet[0] ^ 0xFF)).toString() + '.' +
        (arrayBytIPv4AOctet[1] | (arrayBytIPv4BOctet[1] ^ 0xFF)).toString() + '.' +
        (arrayBytIPv4AOctet[2] | (arrayBytIPv4BOctet[2] ^ 0xFF)).toString() + '.' +
        (arrayBytIPv4AOctet[3] | (arrayBytIPv4BOctet[3] ^ 0xFF)).toString());
}

/**
* This function converts the IPv4 address string to the IPv4 address integer.
*
* @param {string} strIPv4Addr - IPv4 address string.
* @return {number} IPv4 address integer.
*
*/
function toIPv4AddrInteger(strIPv4Addr) {
    const arrayIPv4Octet = strIPv4Addr.split('.');
    return (parseInt(arrayIPv4Octet[0]) * 16777216 + parseInt(arrayIPv4Octet[1]) * 65536 + parseInt(arrayIPv4Octet[2]) * 256 + parseInt(arrayIPv4Octet[3]));
}

/**
* This function converts the IPv4 address integer to the IPv4 address string.
*
* @param {number} intIPv4AddrInteger - IPv4 address integer.
* @return {string} IPv4 address string.
*
*/
function toIPv4AddrString(intIPv4AddrInteger) {
    return [(intIPv4AddrInteger >>> 24) & 0xFF, (intIPv4AddrInteger >>> 16) & 0xFF, (intIPv4AddrInteger >>> 8) & 0xFF, intIPv4AddrInteger & 0xFF].join('.');
}

/**
* This function returns the number of hosts in the specified IPv4 range.
*
* @param {string} strIPv4Range
* @return {number} Number of hosts.
*
* @example
*   strIPv4Range                     Return
*   ---------------------------------------
*   '0.0.0.0-0.0.255.255'         -> 65536
*   '192.168.0.1-192.168.0.1'     -> 1
*   '192.168.0.1-192.168.0.100'   -> 100
*   '192.168.0.1-192.168.100.100' -> 25700
*   '192.168.0.255-192.168.101.0' -> 25602
*/
function getIPv4HostsNumberFromRange(strIPv4Range) { // eslint-disable-line no-unused-vars
    const arrayStrIPv4 = strIPv4Range.split('-');
    return (toIPv4AddrInteger(arrayStrIPv4[1]) - toIPv4AddrInteger(arrayStrIPv4[0]) + 1);
}

/**
* This function converts the IPv4 address range to IPv4 subnets represented in
* CIDR format and saves it into the specified array. However, network
* 0.0.0.0/0 is split into subnetworks 0.0.0.0/1 and 128.0.0.0/1.
*
* @param {number} intStartAddr - Start address integer.
* @param {number} intEndAddr - End address integer.
* @param {Array} arraySave - Array to save IPv4 subnets strings.
*
* @example
*   intStartAddr intEndAddr    arraySave
*   -----------------------------------------------
*   3232235521   3232235521 -> ['192.168.0.1/32']
*   3232235521   3232261220 -> ['192.168.0.1/32',
*                               '192.168.0.2/31',
*                               '192.168.0.4/30',
*                               '192.168.0.8/29',
*                               '192.168.0.16/28',
*                               '192.168.0.32/27',
*                               '192.168.0.64/27',
*                               '192.168.0.96/30',
*                               '192.168.0.100/32']
*   3232235775   3232261376 -> ['192.168.0.255/32',
*                               '192.168.1.0/24',
*                               '192.168.2.0/23',
*                               '192.168.4.0/22',
*                               '192.168.8.0/21',
*                               '192.168.16.0/20',
*                               '192.168.32.0/19',
*                               '192.168.64.0/19',
*                               '192.168.96.0/22',
*                               '192.168.100.0/24',
*                               '192.168.101.0/32]
*/
function makeIPv4SubnetFromRange(intStartAddr, intEndAddr, arraySave) {
    let intSegSize = 2147483648;
    for (let i=1; i<=32; ++i) {
        //
        // Example of round up and round down in 8 bits segment.
        //
        //       |<------ segment ------>|
        //     15 16 17 18 19 20 21 22 23 24
        //          |-> round up to 24
        //         round down to 15 <-|
        //
        const intBlockStart = Math.trunc((intStartAddr + intSegSize - 1) / intSegSize) * intSegSize; // Round up to the start of the next segment.
        const intBlockEnd = (Math.trunc((intEndAddr + 1) / intSegSize) * intSegSize) - 1; // Round down to the end of the previous segment.

        if (intBlockStart <= intBlockEnd) {
            if (intStartAddr < intBlockStart) {
                makeIPv4SubnetFromRange(intStartAddr, intBlockStart - 1, arraySave);
            }
            let intSegStart = intBlockStart;
            let intSegEnd = intSegStart + intSegSize - 1;
            while (intSegEnd <= intBlockEnd) {
                arraySave.push(toIPv4AddrString(intSegStart) + '/' + i);

                intSegStart += intSegSize;
                intSegEnd = intSegStart + intSegSize - 1;
            }
            intStartAddr = intSegStart;

            if (intBlockEnd < intEndAddr) {
                makeIPv4SubnetFromRange(intBlockEnd + 1, intEndAddr, arraySave);
                intEndAddr = intBlockEnd;
            }
        }
        intSegSize = Math.trunc(intSegSize / 2);
    }
}

/**
* This function returns the IPv4 subnets strings array of the specified IPv4
* address range. The subnets are represented in CIDR format.
*
* @param {string} strIPv4Range
* @return {Array} Array of IPv4 subnets strings.
*
* @example
*   strIPv4Range                     Return
*   -----------------------------------------------------
*   '192.168.0.1-192.168.0.1'     -> ['192.168.0.1/32']
*   '192.168.0.1-192.168.0.100'   -> ['192.168.0.1/32',
*                                     '192.168.0.2/31',
*                                     '192.168.0.4/30',
*                                     '192.168.0.8/29',
*                                     '192.168.0.16/28',
*                                     '192.168.0.32/27',
*                                     '192.168.0.64/27',
*                                     '192.168.0.96/30',
*                                     '192.168.0.100/32']
*/
function getIPv4SubnetFromRange(strIPv4Range) { // eslint-disable-line no-unused-vars
    const arrayStrIPv4 = strIPv4Range.split('-');
    const arraySubnet = [];
    makeIPv4SubnetFromRange(toIPv4AddrInteger(arrayStrIPv4[0]), toIPv4AddrInteger(arrayStrIPv4[1]), arraySubnet);
    return arraySubnet;
}

/*
* ============================================================================
* IP address compare functions
* ============================================================================
*/

/**
* This function returns true if the IPv4 address is included within the
* network segment. Otherwise, it is false.
* If the test address is a host address, confirm whether its address is within
* the network segment. If the test address is a network segment, confirm
* whether all addresses of the network segment are within the network segment.
*
* @param {string} strTestIPv4WithPrefixLength
* @param {string} strIPv4SegmentNetworkAddrWithPrefixLength
* @return {boolean}
*   true if the IPv4 address is included within the network segment.
*   Otherwise, it is false.
*
* @example
*   strTestIPv4WithPrefixLength strIPv4SegmentNetworkAddrWithPrefixLength    Return
*   -------------------------------------------------------------------------------
*   '192.168.0.17/24'           '192.168.0.0/24'                          -> true
*   '192.168.0.17/24'           '192.168.1.0/24'                          -> false
*   '192.168.0.17/24'           '192.168.0.0/28'                          -> true
*   '192.168.0.0/24'            '192.168.0.0/28'                          -> false
*   '192.168.0.17/28'           '192.168.0.0/24'                          -> true
*   '192.168.0.0/28'            '192.168.0.0/24'                          -> true
*/
function isIPv4WithPrefixLengthIncludedInSegment(strTestIPv4WithPrefixLength, strIPv4SegmentNetworkAddrWithPrefixLength) {
    const arrayStrTestIPv4           = strTestIPv4WithPrefixLength.split('/');
    const arrayStrIPv4SegmentNetworkAddr = strIPv4SegmentNetworkAddrWithPrefixLength.split('/');

    const strTestIPv4Addr = arrayStrTestIPv4[0];
    let intTestIPv4PrefixLength = parseInt(arrayStrTestIPv4[1]);
    let strTestIPv4NetworkAddr = getIPv4StartAddr(strTestIPv4Addr, getIPv4NetMaskFromPrefixLength(intTestIPv4PrefixLength));
    const intIPv4SegmentPrefixLength = parseInt(arrayStrIPv4SegmentNetworkAddr[1]);
    const strIPv4SegmentNetMask = getIPv4NetMaskFromPrefixLength(intIPv4SegmentPrefixLength);
    const strIPv4SegmentNetworkAddr = getIPv4StartAddr(arrayStrIPv4SegmentNetworkAddr[0], strIPv4SegmentNetMask);

    // If the test address is a host address, change the prefix length to 32.
    if (strTestIPv4NetworkAddr !== strTestIPv4Addr) {
        intTestIPv4PrefixLength = 32;
        strTestIPv4NetworkAddr = strTestIPv4Addr;
    }

    //
    if (intTestIPv4PrefixLength == intIPv4SegmentPrefixLength) {
        if (strTestIPv4NetworkAddr === strIPv4SegmentNetworkAddr) {
            return true;
        }
    } else if (intTestIPv4PrefixLength > intIPv4SegmentPrefixLength) {
        strTestIPv4NetworkAddr = getIPv4StartAddr(strTestIPv4Addr, strIPv4SegmentNetMask);
        if (strTestIPv4NetworkAddr === strIPv4SegmentNetworkAddr) {
            return true;
        }
    }
    return false;
}

/**
* This function returns true if the IPv6 address is included within the
* network segment. Otherwise, it is false.
* If the test address is a host address, confirm whether its address is within
* the network segment. If the test address is a network segment, confirm
* whether all addresses of the network segment are within the network segment.
* Both argument addresses have to be the full represented.
*
* @param {string} strTestIPv6WithPrefixLength
* @param {string} strIPv6SegmentNetworkAddrWithPrefixLength
* @return {boolean}
*   true if the IPv6 address is included within the network segment.
*   Otherwise, it is false.
*
* @example
*   strTestIPv6WithPrefixLength                  strIPv6SegmentNetworkAddrWithPrefixLength       Return
*   ---------------------------------------------------------------------------------------------------
*   '2001:0db8:0001:0002:0003:0004:0005:0006/64' '2001:0db8:0001:0002:0000:0000:0000:0000/64' -> true
*   '2001:0db8:0001:0002:0003:0004:0005:0006/64' '2001:0db8:0001:0003:0000:0000:0000:0000/64' -> false
*   '2001:0db8:0001:0002:0003:0004:0005:0006/64' '2001:0db8:0001:0002:0000:0000:0000:0000/96' -> true
*   '2001:0db8:0001:0002:0000:0000:0000:0000/64' '2001:0db8:0001:0002:0000:0000:0000:0000/96' -> false
*   '2001:0db8:0001:0002:0003:0004:0005:0006/96' '2001:0db8:0001:0002:0000:0000:0000:0000/64' -> true
*   '2001:0db8:0001:0002:0000:0000:0000:0000/96' '2001:0db8:0001:0002:0000:0000:0000:0000/64' -> true
*/
function isIPv6WithPrefixLengthIncludedInSegment(strTestIPv6WithPrefixLength, strIPv6SegmentNetworkAddrWithPrefixLength) {
    const arrayStrTestIPv6           = strTestIPv6WithPrefixLength.split('/');
    const arrayStrIPv6SegmentNetworkAddr = strIPv6SegmentNetworkAddrWithPrefixLength.split('/');

    const strTestIPv6Addr = arrayStrTestIPv6[0];
    let intTestIPv6PrefixLength = parseInt(arrayStrTestIPv6[1]);
    let strTestIPv6NetworkAddr = getIPv6StartAddr(strTestIPv6Addr, getIPv6NetMaskFromPrefixLength(intTestIPv6PrefixLength));
    const intIPv6SegmentPrefixLength = parseInt(arrayStrIPv6SegmentNetworkAddr[1]);
    const strIPv6SegmentNetMask = getIPv6NetMaskFromPrefixLength(intIPv6SegmentPrefixLength);
    const strIPv6SegmentNetworkAddr = getIPv6StartAddr(arrayStrIPv6SegmentNetworkAddr[0], strIPv6SegmentNetMask);

    // If the test address is a host address, change the prefix length to 128.
    if (strTestIPv6NetworkAddr !== strTestIPv6Addr) {
        intTestIPv6PrefixLength = 128;
        strTestIPv6NetworkAddr = strTestIPv6Addr;
    }

    //
    if (intTestIPv6PrefixLength == intIPv6SegmentPrefixLength) {
        if (strTestIPv6NetworkAddr === strIPv6SegmentNetworkAddr) {
            return true;
        }
    } else if (intTestIPv6PrefixLength > intIPv6SegmentPrefixLength) {
        strTestIPv6NetworkAddr = getIPv6StartAddr(strTestIPv6Addr, strIPv6SegmentNetMask);
        if (strTestIPv6NetworkAddr === strIPv6SegmentNetworkAddr) {
            return true;
        }
    }
    return false;
}

/**
* This function compares two IPv4 addresses.
*
* @param {string} strIPv4_1
* @param {string} strIPv4_2
* @return {number}
*    1: IPv4_1 > IPv4_2
*    0: IPv4_1 = IPv4_2
*   -1: IPv4_1 < IPv4_2
*
*/
function compareIPv4(strIPv4_1, strIPv4_2) {
    const arrayStrIPv4Octet_1 = strIPv4_1.split('.');
    const arrayIntIPv4Octet_1 = [];
    for (let i=0; i<4; ++i) {
        arrayIntIPv4Octet_1[i] = parseInt(arrayStrIPv4Octet_1[i]);
    }
    const arrayStrIPv4Octet_2 = strIPv4_2.split('.');
    const arrayIntIPv4Octet_2 = [];
    for (let i=0; i<4; ++i) {
        arrayIntIPv4Octet_2[i] = parseInt(arrayStrIPv4Octet_2[i]);
    }

    for (let i=0; i<4; ++i) {
        if (arrayIntIPv4Octet_1[i] > arrayIntIPv4Octet_2[i]) {
            return 1;
        } else if (arrayIntIPv4Octet_1[i] < arrayIntIPv4Octet_2[i]) {
            return -1;
        }
    }
    return 0;
}

/**
* This function compares two IPv6 addresses.
*
* @param {string} strIPv6_1
* @param {string} strIPv6_2
* @return {number}
*    1: IPv6_1 > IPv6_2
*    0: IPv6_1 = IPv6_2
*   -1: IPv6_1 < IPv6_2
*
*/
function compareIPv6(strIPv6_1, strIPv6_2) {
    const arrayStrIPv6_16bits_1 = strIPv6_1.split(':');
    const arrayIntIPv6_16bits_1 = [];
    for (let i=0; i<8; ++i) {
        arrayIntIPv6_16bits_1[i] = parseInt(arrayStrIPv6_16bits_1[i], 16);
    }
    const arrayStrIPv6_16bits_2 = strIPv6_2.split(':');
    const arrayIntIPv6_16bits_2 = [];
    for (let i=0; i<8; ++i) {
        arrayIntIPv6_16bits_2[i] = parseInt(arrayStrIPv6_16bits_2[i], 16);
    }

    for (let i=0; i<8; ++i) {
        if (arrayIntIPv6_16bits_1[i] > arrayIntIPv6_16bits_2[i]) {
            return 1;
        } else if (arrayIntIPv6_16bits_1[i] < arrayIntIPv6_16bits_2[i]) {
            return -1;
        }
    }
    return 0;
}

/**
* This function returns true if the IPv4 address is within the range.
* Otherwise, it is false.
* If the test address is a host address, confirm whether its address is within
* the range. If the test address is a network segment, confirm whether all
* addresses of the network segment are within the range.
*
* @param {string} strTestIPv4WithPrefixLength
* @param {string} strIPv4Range
* @return {boolean}
*   true if the IPv4 address is within the range.
*   Otherwise, it is false.
*
* @example
*   strTestIPv4WithPrefixLength strIPv4Range                   Return
*   -----------------------------------------------------------------
*   '192.168.0.1/32'            '192.168.0.0-192.168.0.100' -> true
*   '192.168.0.1/32'            '192.168.0.8-192.168.0.100' -> false
*   '192.168.0.0/24'            '192.168.0.0-192.168.0.100' -> false
*   '192.168.0.0/24'            '192.168.0.0-192.168.1.0'   -> true
*   '192.168.0.1/24'            '192.168.0.0-192.168.0.100' -> true
*/
function isIPv4WithPrefixLengthIncludedInRange(strTestIPv4WithPrefixLength, strIPv4Range) {
    const arrayStrTestIPv4 = strTestIPv4WithPrefixLength.split('/');
    const arrayStrIPv4Range = strIPv4Range.split('-');

    const strTestIPv4Addr = arrayStrTestIPv4[0];
    const intTestIPv4PrefixLength = parseInt(arrayStrTestIPv4[1]);
    const strTestIPv4NetMask = getIPv4NetMaskFromPrefixLength(intTestIPv4PrefixLength);
    let strTestIPv4Start = getIPv4StartAddr(strTestIPv4Addr, strTestIPv4NetMask);
    let strTestIPv4End = getIPv4EndAddr(strTestIPv4Addr, strTestIPv4NetMask);

    // If the test address is a host address, change the start address and the end address to the same as the test address.
    if (strTestIPv4Addr !== strTestIPv4Start) {
        strTestIPv4Start = strTestIPv4End = strTestIPv4Addr;
    }

    //
    if (compareIPv4(strTestIPv4Start, arrayStrIPv4Range[0]) >= 0 && compareIPv4(strTestIPv4End, arrayStrIPv4Range[1]) <= 0) {
        return true;
    }
    return false;
}

/**
* This function returns true if the IPv6 address is within the range.
* Otherwise, it is false.
* If the test address is a host address, confirm whether its address is within
* the range. If the test address is a network segment, confirm whether all
* addresses of the network segment are within the range.
* Both argument addresses have to be the full represented.
*
* @param {string} strTestIPv6WithPrefixLength
* @param {string} strIPv6Range
* @return {boolean}
*   true if the IPv6 address is within the range.
*   Otherwise, it is false.
*
* @example
*   strTestIPv6WithPrefixLength                    strIPv6Range                                                                         Return
*   ------------------------------------------------------------------------------------------------------------------------------------------
*   '2001:0db8:0001:0002:0003:0004:0005:0006/128'  '2001:0db8:0001:0002:0003:0004:0005:0000-2001:0db8:0001:0002:0003:0004:0005:0010' -> true
*   '2001:0db8:0001:0002:0003:0004:0005:0006/128'  '2001:0db8:0001:0002:0003:0004:0005:0008-2001:0db8:0001:0002:0003:0004:0005:0010' -> false
*   '2001:0db8:0001:0002:0000:0000:0000:0000/64'   '2001:0db8:0001:0002:0003:0004:0005:0000-2001:0db8:0001:0002:0003:0004:0005:0010' -> false
*   '2001:0db8:0001:0002:0000:0000:0000:0000/64'   '2001:0db8:0001:0002:0000:0000:0000:0000-2001:0db8:0001:0003:0000:0000:0000:0000' -> true
*   '2001:0db8:0001:0002:0003:0004:0005:0006/64'   '2001:0db8:0001:0002:0003:0004:0005:0000-2001:0db8:0001:0002:0003:0004:0005:0010' -> true
*/
function isIPv6WithPrefixLengthIncludedInRange(strTestIPv6WithPrefixLength, strIPv6Range) {
    const arrayStrTestIPv6 = strTestIPv6WithPrefixLength.split('/');
    const arrayStrIPv6Range = strIPv6Range.split('-');

    const strTestIPv6Addr = arrayStrTestIPv6[0];
    const intTestIPv6PrefixLength = parseInt(arrayStrTestIPv6[1]);
    const strTestIPv6NetMask = getIPv6NetMaskFromPrefixLength(intTestIPv6PrefixLength);
    let strTestIPv6Start = getIPv6StartAddr(strTestIPv6Addr, strTestIPv6NetMask);
    let strTestIPv6End = getIPv6EndAddr(strTestIPv6Addr, strTestIPv6NetMask);

    // If the test address is a host address, change the start address and the end address to the same as the test address.
    if (strTestIPv6Addr !== strTestIPv6Start) {
        strTestIPv6Start = strTestIPv6End = strTestIPv6Addr;
    }

    //
    if (compareIPv6(strTestIPv6Start, arrayStrIPv6Range[0]) >= 0 && compareIPv6(strTestIPv6End, arrayStrIPv6Range[1]) <= 0) {
        return true;
    }
    return false;
}

/**
* This function returns true if the IPv4 address matches the Cisco-style
* wildcard address. Otherwise, it is false. If the IPv4 address is a host
* address, test whether its address matches. If a network segment, test
* whether all addresses of the network segment match.
*
* @param {string} strTestIPv4WithPrefixLength
* @param {string} strIPv4AddrWithWildcardMask
* @return {boolean}
*   true if the IPv4 address matches the wildcard address.
*   Otherwise, it is false.
*
* @example
*   strTestIPv4WithPrefixLength strIPv4AddrWithWildcardMask    Return
*   -----------------------------------------------------------------
*   '192.168.0.0/32'            '192.168.0.0/0.0.0.255'     -> true
*   '192.168.0.1/32'            '192.168.0.0/0.0.0.255'     -> true
*   '192.168.0.2/32'            '192.168.0.0/0.0.0.255'     -> true
*   '192.168.0.3/32'            '192.168.0.0/0.0.0.255'     -> true
*   '192.168.0.0/32'            '192.168.0.1/0.0.0.254'     -> false
*   '192.168.0.1/32'            '192.168.0.1/0.0.0.254'     -> true
*   '192.168.0.2/32'            '192.168.0.1/0.0.0.254'     -> false
*   '192.168.0.3/32'            '192.168.0.1/0.0.0.254'     -> true
*   '192.168.0.0/31'            '192.168.0.0/0.0.0.2'       -> false
*   '192.168.0.0/31'            '192.168.0.1/0.0.0.2'       -> false
*/
function isIPv4WithPrefixLengthIncludedInCiscoWildcardAddr(strTestIPv4WithPrefixLength, strIPv4AddrWithWildcardMask) { // eslint-disable-line no-unused-vars
    const arrayStrTestIPv4     = strTestIPv4WithPrefixLength.split('/');
    const arrayStrIPv4Wildcard = strIPv4AddrWithWildcardMask.split('/');

    const strTestIPv4Addr = arrayStrTestIPv4[0];
    const intTestIPv4PrefixLength = parseInt(arrayStrTestIPv4[1]);
    const strTestIPv4NetworkAddr = getIPv4StartAddr(strTestIPv4Addr, getIPv4NetMaskFromPrefixLength(intTestIPv4PrefixLength));

    const strIPv4WildcardAddr = arrayStrIPv4Wildcard[0];
    const strIPv4WildcardMask = arrayStrIPv4Wildcard[1];
    const strIPv4WildcardAddrMaskbits0 = getBitwiseANDedIPv4AddrWithInvertBits(strIPv4WildcardAddr, strIPv4WildcardMask);
    const strIPv4WildcardAddrMaskbits1 = getBitwiseORedIPv4Addr(strIPv4WildcardAddr, strIPv4WildcardMask);

    //
    if (intTestIPv4PrefixLength == 32 || strTestIPv4NetworkAddr !== strTestIPv4Addr) {
        const strTestIPv4AddrMaskbits0 = getBitwiseANDedIPv4AddrWithInvertBits(strTestIPv4Addr, strIPv4WildcardMask);
        const strTestIPv4AddrMaskbits1 = getBitwiseORedIPv4Addr(strTestIPv4Addr, strIPv4WildcardMask);

        if ((strTestIPv4AddrMaskbits0 === strIPv4WildcardAddrMaskbits0) &&
            (strTestIPv4AddrMaskbits1 === strIPv4WildcardAddrMaskbits1)) {
            return true;
        }
    } else {
        const strTestIPv4BroadcastAddr = getIPv4EndAddr(strTestIPv4Addr, getIPv4NetMaskFromPrefixLength(intTestIPv4PrefixLength));
        const strTestIPv4NetworkAddrMaskbits0 = getBitwiseANDedIPv4AddrWithInvertBits(strTestIPv4NetworkAddr, strIPv4WildcardMask);
        const strTestIPv4NetworkAddrMaskbits1 = getBitwiseORedIPv4Addr(strTestIPv4NetworkAddr, strIPv4WildcardMask);
        const strTestIPv4BroadcastAddrMaskbits0 = getBitwiseANDedIPv4AddrWithInvertBits(strTestIPv4BroadcastAddr, strIPv4WildcardMask);
        const strTestIPv4BroadcastAddrMaskbits1 = getBitwiseORedIPv4Addr(strTestIPv4BroadcastAddr, strIPv4WildcardMask);

        if ((strTestIPv4NetworkAddrMaskbits0 === strIPv4WildcardAddrMaskbits0) &&
            (strTestIPv4NetworkAddrMaskbits1 === strIPv4WildcardAddrMaskbits1) &&
            (strTestIPv4BroadcastAddrMaskbits0 === strIPv4WildcardAddrMaskbits0) &&
            (strTestIPv4BroadcastAddrMaskbits1 === strIPv4WildcardAddrMaskbits1)) {
            return true;
        }
    }
    return false;
}

/**
* This function returns true if the IPv4 address matches the Fortinet-style
* wildcard address. Otherwise, it is false. If the IPv4 address is a host
* address, test whether its address matches. If a network segment, test
* whether all addresses of the network segment match.
*
* @param {string} strTestIPv4WithPrefixLength
* @param {string} strIPv4AddrWithWildcardMask
* @return {boolean}
*   true if the IPv4 address matches the wildcard address.
*   Otherwise, it is false.
*
* @example
*   strTestIPv4WithPrefixLength strIPv4AddrWithWildcardMask      Return
*   -------------------------------------------------------------------
*   '192.168.0.0/32'            '192.168.0.0/255.255.255.0'   -> true
*   '192.168.0.1/32'            '192.168.0.0/255.255.255.0'   -> true
*   '192.168.0.2/32'            '192.168.0.0/255.255.255.0'   -> true
*   '192.168.0.3/32'            '192.168.0.0/255.255.255.0'   -> true
*   '192.168.0.0/32'            '192.168.0.1/255.255.255.1'   -> false
*   '192.168.0.1/32'            '192.168.0.1/255.255.255.1'   -> true
*   '192.168.0.2/32'            '192.168.0.1/255.255.255.1'   -> false
*   '192.168.0.3/32'            '192.168.0.1/255.255.255.1'   -> true
*   '192.168.0.0/31'            '192.168.0.0/255.255.255.253' -> false
*   '192.168.0.0/31'            '192.168.0.1/255.255.255.253' -> false
*/
function isIPv4WithPrefixLengthIncludedInFortinetWildcardAddr(strTestIPv4WithPrefixLength, strIPv4AddrWithWildcardMask) {
    const arrayStrTestIPv4     = strTestIPv4WithPrefixLength.split('/');
    const arrayStrIPv4Wildcard = strIPv4AddrWithWildcardMask.split('/');

    const strTestIPv4Addr = arrayStrTestIPv4[0];
    const intTestIPv4PrefixLength = parseInt(arrayStrTestIPv4[1]);
    const strTestIPv4NetworkAddr = getIPv4StartAddr(strTestIPv4Addr, getIPv4NetMaskFromPrefixLength(intTestIPv4PrefixLength));

    const strIPv4WildcardAddr = arrayStrIPv4Wildcard[0];
    const strIPv4WildcardMask = arrayStrIPv4Wildcard[1];
    const strIPv4WildcardAddrMaskbits0 = getBitwiseANDedIPv4Addr(strIPv4WildcardAddr, strIPv4WildcardMask);
    const strIPv4WildcardAddrMaskbits1 = getBitwiseORedIPv4AddrWithInvertBits(strIPv4WildcardAddr, strIPv4WildcardMask);

    //
    if (intTestIPv4PrefixLength == 32 || strTestIPv4NetworkAddr !== strTestIPv4Addr) {
        const strTestIPv4AddrMaskbits0 = getBitwiseANDedIPv4Addr(strTestIPv4Addr, strIPv4WildcardMask);
        const strTestIPv4AddrMaskbits1 = getBitwiseORedIPv4AddrWithInvertBits(strTestIPv4Addr, strIPv4WildcardMask);

        if ((strTestIPv4AddrMaskbits0 === strIPv4WildcardAddrMaskbits0) &&
            (strTestIPv4AddrMaskbits1 === strIPv4WildcardAddrMaskbits1)) {
            return true;
        }
    } else {
        const strTestIPv4BroadcastAddr = getIPv4EndAddr(strTestIPv4Addr, getIPv4NetMaskFromPrefixLength(intTestIPv4PrefixLength));
        const strTestIPv4NetworkAddrMaskbits0 = getBitwiseANDedIPv4Addr(strTestIPv4NetworkAddr, strIPv4WildcardMask);
        const strTestIPv4NetworkAddrMaskbits1 = getBitwiseORedIPv4AddrWithInvertBits(strTestIPv4NetworkAddr, strIPv4WildcardMask);
        const strTestIPv4BroadcastAddrMaskbits0 = getBitwiseANDedIPv4Addr(strTestIPv4BroadcastAddr, strIPv4WildcardMask);
        const strTestIPv4BroadcastAddrMaskbits1 = getBitwiseORedIPv4AddrWithInvertBits(strTestIPv4BroadcastAddr, strIPv4WildcardMask);

        if ((strTestIPv4NetworkAddrMaskbits0 === strIPv4WildcardAddrMaskbits0) &&
            (strTestIPv4NetworkAddrMaskbits1 === strIPv4WildcardAddrMaskbits1) &&
            (strTestIPv4BroadcastAddrMaskbits0 === strIPv4WildcardAddrMaskbits0) &&
            (strTestIPv4BroadcastAddrMaskbits1 === strIPv4WildcardAddrMaskbits1)) {
            return true;
        }
    }
    return false;
}

/*
* ============================================================================
* Normalization functions
* ============================================================================
*/

/**
* This function normalizes the address string of an address object in the
* 'firewall address' configuration and returns the object that contains the
* array of a normalized address string. If the address type is 'ipmask', the
* normalized address string is represented in CIDR format. If the address type
* is 'iprange', the start-ip and end-ip are combined with '-.' The wildcard
* address is combined with '/.' If the address type is 'geography', the
* normalized string is the country name with the prefix 'geo:'. The prefix
* 'fqdn:' is added if the address type is 'fqdn' or 'wildcard-fqdn.'
*
* @param {Object} objParam -
*   Parameter object of an address object to normalize.
* @return {Object} Object that contains the normalized address string.
*
* @example
*   objParam['type'] objParam['param1'] objParam['param2'] objParam['comment']    Return['value']               Return['comment']
*   -----------------------------------------------------------------------------------------------------------------------------
*   'ipmask'         '192.168.0.0'      '255.255.255.0'    'MyComment.'        -> ['192.168.0.0/24'           ] 'MyComment.'
*   'iprange'        '192.168.0.1'      '192.168.0.100'    'My comment.'       -> ['192.168.0.1-192.168.0.100'] 'My comment.'
*   'wildcard'       '192.168.0.0'      '255.255.0.255'    ''                  -> ['192.168.0.0/255.255.0.255'] ''
*   'fqdn'           'example.com'      ''                 'Comment'           -> ['fqdn:example.com'         ] 'Comment'
*   'wildcard-fqdn'  '*.example.com'    ''                 'Comment'           -> ['fqdn:*.example.com'       ] 'Comment'
*   'geography'      'US'               ''                 'Comment'           -> ['geo:US'                   ] 'Comment'
*   'UNKNOWN'        ''                 ''                 'Comment'           -> ['undefined'                ] 'Comment'
*   ''               ''                 ''                 'Comment'           -> ['undefined'                ] 'Comment'
*/
function normalizeFirewallIPv4Address(objParam) {
    const strParam1 = objParam['param1'];
    const strParam2 = objParam['param2'];
    const objReturn = {};
    const arrayValue = [];
    arrayValue[0] = 'undefined';

    switch (objParam['type']) {
    case 'ipmask':
        if (strParam1 !== '' && strParam2 !== '') {
            arrayValue[0] = getIPv4AddrWithPrefixLength(strParam1, strParam2);
        }
        break;
    case 'iprange':
        if (strParam1 !== '' && strParam2 !== '') {
            arrayValue[0] = strParam1 + '-' + strParam2;
        }
        break;
    case 'wildcard':
        if (strParam1 !== '' && strParam2 !== '') {
            arrayValue[0] = strParam1 + '/' + strParam2;
        }
        break;
    case 'fqdn':
    case 'wildcard-fqdn':
        if (strParam1 !== '') {
            arrayValue[0] = 'fqdn:' + strParam1;
        }
        break;
    case 'geography':
        if (strParam1 !== '') {
            arrayValue[0] = 'geo:' + strParam1;
        }
        break;
    }
    objReturn['value'] = arrayValue.unique();
    objReturn['comment'] = objParam['comment'];
    return objReturn;
}

/**
* This function normalizes the address string of an address object in the
* 'firewall address6' configuration and returns the object that contains the
* array of a normalized address string. If the address type is 'ip6,' the
* normalized address string is adapted to the full represented. If the address
* type is 'iprange,' the start-ip and end-ip are combined with '-.' The prefix
* 'fqdn:' is added if the address type is 'fqdn.'
*
* @param {Object} objParam -
*   Parameter object of an address object to normalize.
* @return {Object} Object that contains the normalized address string.
*
* @example
*   objParam['type'] objParam['param1']         objParam['param2'] objParam['comment']    Return['value']                                                                     Return['comment']
*   -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   'ipprefix'       '2001:0db8:0002:0003::/64' ''                 'MyComment.'        -> ['2001:0db8:0002:0003:0000:0000:0000:0000/64'                                     ] 'MyComment.'
*   'iprange'        '2001:0db8::0001'          '2001:0db8::0100'  'My comment.'       -> ['2001:0db8:0000:0000:0000:0000:0000:0001-2001:0db8:0000:0000:0000:0000:0000:0100'] 'My comment.'
*   'fqdn'           'example.com'              ''                 ''                  -> ['fqdn:example.com'                                                               ] ''
*   'UNKNOWN'        ''                         ''                 'Comment'           -> ['undefined'                                                                      ] 'Comment'
*   ''               ''                         ''                 'Comment'           -> ['undefined'                                                                      ] 'Comment'
*/
function normalizeFirewallIPv6Address(objParam) {
    const strParam1 = objParam['param1'];
    const strParam2 = objParam['param2'];
    const objReturn = {};
    const arrayValue = [];
    arrayValue[0] = 'undefined';

    switch (objParam['type']) {
    case 'ipprefix':
        arrayValue[0] = strParam1 === '' ? 'undefined' : getIPv6FullRepresentedAddrWithPrefixLength(strParam1);
        break;
    case 'iprange':
        if (strParam1 !== '' && strParam2 !== '') {
            arrayValue[0] = getIPv6FullRepresentedAddr(strParam1) + '-' + getIPv6FullRepresentedAddr(strParam2);
        }
        break;
    case 'fqdn':
        if (strParam1 !== '') {
            arrayValue[0] = 'fqdn:' + strParam1;
        }
        break;
    }
    objReturn['value'] = arrayValue.unique();
    objReturn['comment'] = objParam['comment'];
    return objReturn;
}

/**
* This function normalizes the address string of a multicast address object in
* the 'firewall multicast-address' configuration and returns the object that
* contains the array of a normalized address string. If the address type is
* 'broadcastmask', the normalized address string is represented in CIDR format.
* If the address type is 'multicastrange', the start-ip and end-ip are
* combined with '-.'
*
* @param {Object} objParam -
*   Parameter object of a multicast address object to normalize.
* @return {Object} Object that contains the normalized address string.
*
* @example
*   objParam['type'] objParam['param1'] objParam['param2'] objParam['comment']    Return['value']           Return['comment']
*   -------------------------------------------------------------------------------------------------------------------------
*   'broadcastmask'  '224.0.0.0'        '255.255.255.0'    'MyComment.'        -> ['224.0.0.0/24'         ] 'MyComment.'
*   'multicastrange' '224.0.0.1'        '224.0.0.100'      'My comment.'       -> ['224.0.0.1-224.0.0.100'] 'My comment.'
*   'UNKNOWN'        ''                 ''                 'Comment'           -> ['undefined'            ] 'Comment'
*   ''               ''                 ''                 'Comment'           -> ['undefined'            ] 'Comment'
*/
function normalizeFirewallIPv4MulticastAddress(objParam) {
    const strParam1 = objParam['param1'];
    const strParam2 = objParam['param2'];
    const objReturn = {};
    const arrayValue = [];
    arrayValue[0] = 'undefined';

    switch (objParam['type']) {
    case 'broadcastmask':
        if (strParam1 !== '' && strParam2 !== '') {
            arrayValue[0] = getIPv4AddrWithPrefixLength(strParam1, strParam2);
        }
        break;
    case 'multicastrange':
        if (strParam1 !== '' && strParam2 !== '') {
            arrayValue[0] = strParam1 + '-' + strParam2;
        }
        break;
    }
    objReturn['value'] = arrayValue.unique();
    objReturn['comment'] = objParam['comment'];
    return objReturn;
}

/**
* This function normalizes the address string of a multicast address object in
* the 'firewall multicast-address6' configuration and returns the object that
* contains the array of a normalized address string.
*
* @param {Object} objParam -
*   Parameter object of a multicast address object to normalize.
* @return {Object} Object that contains the normalized address string.
*
* @example
*   objParam['param1'] objParam['comment']    Return['value']                                 Return['comment']
*   -----------------------------------------------------------------------------------------------------------
*   'ff00::1/128'      'MyComment.'        -> ['ff00:0000:0000:0000:0000:0000:0000:0001/128'] 'MyComment.'
*   ''                 'My comment.'       -> ['undefined'                                  ] 'My comment.'
*/
function normalizeFirewallIPv6MulticastAddress(objParam) {
    const strParam1 = objParam['param1'];
    const objReturn = {};
    const arrayValue = [];

    arrayValue[0] = strParam1 === '' ? 'undefined' : getIPv6FullRepresentedAddrWithPrefixLength(strParam1);

    objReturn['value'] = arrayValue.unique();
    objReturn['comment'] = objParam['comment'];
    return objReturn;
}

/**
* This function returns the operator-port style condition string of the
* specified port condition string.
*
* @param {string} strPortCondition - Port condtion string.
* @return {string} Operator-port style condition string.
*
* @example
*   strPortCondition    Return
*   ----------------------------------------
*   '80'             -> 'eq/80'
*   '20-21'          -> 'range/20-21'
*   '20-'            -> 'range/20-undefined'
*   'UNKNOWN'        -> 'eq/UNKNOWN'
*   ''               -> 'eq/any'
*/
function getOperPortStyleConditionStringFromPortCondition(strPortCondition) {
    let strNormalizedPortCondition = 'eq/any';
    if (strPortCondition && strPortCondition !== '') {
        if (strPortCondition.indexOf('-') == -1) { // Port number only or unknown condition.
            strNormalizedPortCondition = 'eq/' + strPortCondition;
        } else { // Range.
            const array = strPortCondition.split(/-/);
            strNormalizedPortCondition = 'range/' + (array[0] === '' ? 'undefined' : array[0]) + '-' + (array[1] ? array[1] : 'undefined');
        }
    }
    return strNormalizedPortCondition;
}

/**
* This function returns the array of service port condition strings for the
* specified service parameters. At the tail of the service port condition
* string, the service destination address is added.
*
* @param {string} strProtocolNumber - Protocol number.
* @param {string} strTcpUdpOrSctpPortRange -
*   tcp-portrange, udp-portrange, or sctp-portrange of service object.
* @param {string} strIpRange - Iprange of service object.
* @param {string} strFqdn - Fqdn of service object.
* @return {Array} Array of service port condition strings.
*
* @example
*   strProtocolNumber strTcpUdpOrSctpPortRange              strIpRange                  strFqdn              Return
*   ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   '6'               '80'                                  ''                          ''                -> ['6/eq/any/eq/80;0/0'                                                                             ]
*   '6'               '80 80'                               '192.168.0.1'               ''                -> ['6/eq/any/eq/80;192.168.0.1/32'                                                                  ]
*   '17'              '123 :1-65535'                        '192.168.0.1-192.168.0.100' ''                -> ['17/eq/any/eq/123;192.168.0.1-192.168.0.100','17/range/1-65535/eq/any;192.168.0.1-192.168.0.100' ]
*   '17'              '123:10000-20000 161-162'             ''                          'www.example.com' -> ['17/range/10000-20000/eq/123;fqdn:www.example.com','17/eq/any/range/161-162;fqdn:www.example.com']
*   '132'             '4321-4322:1-65535 :1-65535'          '0.0.0.0'                   ''                -> ['132/range/1-65535/range/4321-4322;0/0','132/range/1-65535/eq/any;0/0'                           ]
*   '132'             '4321-4322:1-65535 4321-4322:1-65535' ''                          ''                -> ['132/range/1-65535/range/4321-4322;0/0'                                                          ]
*   '6'               '-'                                   ''                          ''                -> ['6/eq/any/range/undefined-undefined;0/0'                                                         ]
*   '6'               ':'                                   ''                          ''                -> ['6/eq/any/eq/any;0/0'                                                                            ]
*/
function getServicePortConditionArray(strProtocolNumber, strTcpUdpOrSctpPortRange, strIpRange, strFqdn) {
    const arrayReturn = [];

    let strServiceDstAddr = '0/0';
    if (strIpRange !== '') {
        if (strIpRange === '0.0.0.0') { // Default value.
            // Nothing to do.
        } else if (strIpRange.indexOf('-') == -1) {
            strServiceDstAddr = strIpRange + '/32';
        } else {
            strServiceDstAddr = strIpRange;
        }
    } else if (strFqdn !== '') {
        strServiceDstAddr = 'fqdn:' + strFqdn;
    }

    const arrayPortRange = strTcpUdpOrSctpPortRange.split(/\s+/).unique();
    for (let i=0; i<arrayPortRange.length; ++i) {
        const arrayPortCondition = arrayPortRange[i].split(':');
        arrayReturn[i] = strProtocolNumber + '/' +
            getOperPortStyleConditionStringFromPortCondition(arrayPortCondition[1]) + '/' +
            getOperPortStyleConditionStringFromPortCondition(arrayPortCondition[0]) + ';' + strServiceDstAddr;
    }
    return arrayReturn;
}

/**
* This function normalizes the service string of a service object in the
* 'firewall service custom' configuration and returns the object that contains
* the array of normalized service strings. The parameters that use for
* normalization are the following.
*
*   - protocol
*   - protocol-number
*   - icmptype and icmpcode
*   - tcp-portrange, udp-portrange, and sctp-portrange
*
* Protocol name is converted to its number string. However, if the protocol
* number is 0, it is changed to 'ip.'
*
* @param {Object} objParam - Parameter object of a service object to normalize.
* @return {Object}
*   Object that contains the string of the normalized service condition.
*
* @example
*   ip:
*       objParam['protocol'] objParam['protocol_number'] objParam['comment']    Return['value'] Return['protocol_type'] Return['comment']
*       ---------------------------------------------------------------------------------------------------------------------------------
*       'IP'                 '0'                         'MyComment.'        -> ['ip;-']        PROTOCOL_TYPE_BIT_IP    'MyComment.'
*       'IP'                 '89'                        'My comment.'       -> ['89;-']        PROTOCOL_TYPE_BIT_IP    'My comment.'
*   icmp or icmp6:
*       objParam['protocol'] objParam['icmptype'] objParam['icmpcode'] objParam['comment']    Return['value']     Return['protocol_type']      Return['comment']
*       --------------------------------------------------------------------------------------------------------------------------------------------------------
*       'ICMP'               ''                   ''                   'MyComment.'        -> ['1/any/any;-'    ] PROTOCOL_TYPE_BIT_ICMP_ICMP6 'MyComment.'
*       'ICMP'               '0'                  ''                   'My comment.'       -> ['1/0/any;-'      ] PROTOCOL_TYPE_BIT_ICMP_ICMP6 'My comment.'
*       'ICMP6'              '0'                  '255'                ''                  -> ['58/0/255;-'     ] PROTOCOL_TYPE_BIT_ICMP_ICMP6 ''
*   tcp, udp, or sctp:
*       objParam['protocol'] objParam['tcp_portrange'] objParam['udp_portrange'] objParam['sctp_portrange']   objParam['iprange']         objParam['fqdn']       objParam['comment']    Return['value']                                                                                                                                                               Return['protocol_type']        Return['comment']
*       --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*       'TCP/UDP/SCTP'       '80'                      ''                        ''                           ''                          ''                     'MyComment.'        -> ['6/eq/any/eq/80;0/0'                                                                                                                                                       ] PROTOCOL_TYPE_BIT_TCP_UDP_SCTP 'MyComment.'
*       'TCP/UDP/SCTP'       ''                        ':1-65535'                ''                           '192.168.0.1'               ''                     'My comment.'       -> ['17/range/1-65535/eq/any;192.168.0.1/32'                                                                                                                                   ] PROTOCOL_TYPE_BIT_TCP_UDP_SCTP 'My comment.'
*       'TCP/UDP/SCTP'       ''                        ''                        '4321-4322:10000-20000'      ''                          ''                     ''                  -> ['132/range/10000-20000/range/4321-4322;0/0'                                                                                                                                ] PROTOCOL_TYPE_BIT_TCP_UDP_SCTP ''
*       'TCP/UDP/SCTP'       '20-21'                   '123:10000-20000'         ''                           '192.168.0.1-192.168.0.100' ''                     'Comment'           -> ['6/eq/any/range/20-21;192.168.0.1-192.168.0.100','17/range/10000-20000/eq/123;192.168.0.1-192.168.0.100'                                                                   ] PROTOCOL_TYPE_BIT_TCP_UDP_SCTP 'Comment'
*       'TCP/UDP/SCTP'       ':10000-20000'            ''                        '4321'                       ''                          'fqdn:www.example.com' 'Comment'           -> ['6/range/10000-20000/eq/any;fqdn:www.example.com','132/eq/any/eq/4321;fqdn:www.example.com'                                                                                ] PROTOCOL_TYPE_BIT_TCP_UDP_SCTP 'Comment'
*       'TCP/UDP/SCTP'       '20-21:10000'             '123'                     ':1-65535'                   ''                          ''                     'Comment'           -> ['6/eq/10000/range/20-21;0/0','17/eq/any/eq/123;0/0','132/range/1-65535/eq/any;0/0'                                                                                         ] PROTOCOL_TYPE_BIT_TCP_UDP_SCTP 'Comment'
*       'TCP/UDP/SCTP'       '80 20-21:10000'          '123 161-162'             '4321-4322:10000-20000 4323' ''                          ''                     'Comment'           -> ['6/eq/any/eq/80;0/0','6/eq/10000/range/20-21;0/0','17/eq/any/eq/123;0/0','17/eq/any/range/161-162;0/0','132/range/10000-20000/range/4321-4322;0/0','132/eq/any/eq/4323;0/0'] PROTOCOL_TYPE_BIT_TCP_UDP_SCTP 'Comment'
*   others:
*       objParam['protocol'] objParam['comment']    Return['value']       Return['protocol_type']       Return['comment']
*       -----------------------------------------------------------------------------------------------------------------
*       'UNKNOWN'            'MyComment.'        -> ['UNKNOWN;UNKNOWN']   PROTOCOL_TYPE_BIT_UNSUPPORTED 'MyComment.'
*       ''                   'My comment.'       -> ['undefined;-'    ]   PROTOCOL_TYPE_BIT_NONE        'My comment.'
*/
function normalizeFirewallServiceCustom(objParam) {
    const objReturn = {};
    const arrayValue = [];
    switch (objParam['protocol']) {
    case 'IP':
        arrayValue[0] = (Number.isInteger(+objParam['protocol_number']) && objParam['protocol_number'] !== '0' && objParam['protocol_number'] !== '') ? objParam['protocol_number'] : 'ip';
        arrayValue[0] += ';-';
        break;
    case 'ICMP':
        arrayValue[0] = '1/'  + (objParam['icmptype'] === '' ? 'any' : objParam['icmptype']) + '/' + (objParam['icmpcode'] === '' ? 'any' : objParam['icmpcode']);
        arrayValue[0] += ';-';
        break;
    case 'ICMP6':
        arrayValue[0] = '58/' + (objParam['icmptype'] === '' ? 'any' : objParam['icmptype']) + '/' + (objParam['icmpcode'] === '' ? 'any' : objParam['icmpcode']);
        arrayValue[0] += ';-';
        break;
    case 'TCP/UDP/SCTP':
        if (objParam['tcp_portrange'] !== '') {
            arrayValue.push(...getServicePortConditionArray('6', objParam['tcp_portrange'], objParam['iprange'], objParam['fqdn']));
        }
        if (objParam['udp_portrange'] !== '') {
            arrayValue.push(...getServicePortConditionArray('17', objParam['udp_portrange'], objParam['iprange'], objParam['fqdn']));
        }
        if (objParam['sctp_portrange'] !== '') {
            arrayValue.push(...getServicePortConditionArray('132', objParam['sctp_portrange'], objParam['iprange'], objParam['fqdn']));
        }
        break;
    case '':
        arrayValue[0] = 'undefined;-';
        break;
    default: // Unsupported protocol.
        arrayValue[0] = objParam['protocol'] + ';' + objParam['protocol'];
        break;
    }
    objReturn['value'] = arrayValue.unique();
    objReturn['protocol_type'] = getProtocolTypeBitsOfArray(objReturn['value']);
    objReturn['comment'] = objParam['comment'];
    return objReturn;
}

/**
* This function flattens the specified members to those values and returns the
* flattened values array. If two or more members flatten, all flattened values
* are contained in an array. However, duplicate values are stripped.
*
* @param {Object} objObjectOrGroupObject -
*   Address object, address-group object, service object, or service-group
*   object.
* @param {string} strMembers - Members that to flatten.
* @return {Array} Array of flattened values.
*
* @example
*   objObjectOrGroupObject                                                          strMembers           Return
*   ------------------------------------------------------------------------------------------------------------------
*   {KEY11:{value:['ABC'      ],comment:''},KEY12:{value:['DEF','GHI'],comment:''}} '"KEY11"'         -> ['ABC'      ]
*   {KEY12:{value:['DEF','GHI'],comment:''},KEY13:{value:['DEF','DEF'],comment:''}} '"KEY12" "KEY13"' -> ['DEF','GHI']
*   {KEY11:{value:['ABC'      ],comment:''}                                       } '"NOKEY"'         -> [           ]
*/
function flattenMember(objObjectOrGroupObject, strMembers) {
    const arrayValue = [];
    const arrayMember = strMembers.trimString('"').split('" "');
    for (let i=0; i<arrayMember.length; ++i) {
        if (objObjectOrGroupObject[arrayMember[i]]) {
            arrayValue.push(...objObjectOrGroupObject[arrayMember[i]].value);
        }
    }
    return arrayValue.unique();
}

/**
* This function flattens members of an address-group object in the 'firewall
* addrgrp' or 'firewall addrgrp6' configuration and returns the object that
* contains the array of normalized address strings. However, duplicate
* addresses are stripped.
*
* @param {Object} objParam -
*   Parameter object of an address-group object to flatten.
* @param {Object} objFirewallAddress -
*   g_Domain_Data[].address4 or g_Domain_Data[].address6.
* @param {Object} objFirewallAddressGroup -
*   g_Domain_Data[].addrgrp4 or g_Domain_Data[].addrgrp6.
* @return {Object} Array of normalized address strings.
*
* @example
*   Variables state when calls.
*   -------------------------------------------------------------------------------------------------------
*   objFirewallAddress['ADDR11']       = {value:['192.168.0.1/32'                             ],comment:''}
*   objFirewallAddress['ADDR21']       = {value:['0.0.0.0/0','172.16.0.0/16'                  ],comment:''}
*   objFirewallAddress['ADDR22']       = {value:['192.168.0.1/32','172.16.0.0/16'             ],comment:''}
*   objFirewallAddressGroup['ADDRG11'] = {value:['10.0.0.0/8'                                 ],comment:''}
*   objFirewallAddressGroup['ADDRG21'] = {value:['192.168.0.1/32','192.168.0.0/24'            ],comment:''}
*   objFirewallAddress['ADDR31']       = {value:['2001:0db8:0000:0000:0000:0000:0000:0001/128'],comment:''}
*   objFirewallAddress['ADDR32']       = {value:['2001:0db8:0002:0003:0000:0000:0000:0000/64' ],comment:''}
*
*   objParam['member']                      objParam['comment']    Return['value']                                                                              Return['comment']
*   -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   '"ADDR11"'                              'MyComment.'        -> ['192.168.0.1/32'                                                                          ] 'MyComment.'
*   '"ADDR31" "ADDR32'                      'My comment.'       -> ['2001:0db8:0000:0000:0000:0000:0000:0001/128','2001:0db8:0002:0003:0000:0000:0000:0000/64'] 'My comment.'
*   '"ADDRG11"'                             'Comment'           -> ['10.0.0.0/8'                                                                              ] 'Comment'
*   '"ADDR21" "ADDR22" "ADDRG11" "ADDRG21"' 'Comment'           -> ['0.0.0.0/0','172.16.0.0/16','192.168.0.1/32','10.0.0.0/8','192.168.0.0/24'                ] 'Comment'
*   '"UNKNOWN"'                             'Comment'           -> [                                                                                          ] 'Comment'
*/
function normalizeFirewallAddressGroup(objParam, objFirewallAddress, objFirewallAddressGroup) {
    const objReturn = {};
    const arrayValue = flattenMember(objFirewallAddress, objParam['member']);
    arrayValue.push(...flattenMember(objFirewallAddressGroup, objParam['member']));
    objReturn['value'] = arrayValue.unique();
    objReturn['comment'] = objParam['comment'];
    return objReturn;
}

/**
* This function flattens members of a service-group object in the 'firewall
* service group' configuration and returns the object that contains the array
* of normalized service strings. However, duplicate services are stripped.
*
* @param {Object} objParam -
*   Parameter object of a service-group object to flatten.
* @param {Object} objFirewallServiceCustom - g_Domain_Data[].service_custom
* @param {Object} objFirewallServiceGroup - g_Domain_Data[].service_group
* @return {Object} Array of normalized service strings.
*
* @example
*   Variables state when calls.
*   ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   objFirewallServiceCustom['SRVC11'] = {value:['1/any/any;-'                           ],protocol_type:PROTOCOL_TYPE_BIT_ICMP_ICMP6                               },comment:''
*   objFirewallServiceCustom['SRVC12'] = {value:['6/eq/any/eq/80;0/0'                    ],protocol_type:PROTOCOL_TYPE_BIT_TCP_UDP_SCTP                             },comment:''
*   objFirewallServiceCustom['SRVC21'] = {value:['ip;-','17/eq/any/eq/123;192.168.0.1/32'],protocol_type:PROTOCOL_TYPE_BIT_IP|PROTOCOL_TYPE_BIT_TCP_UDP_SCTP        },comment:''
*   objFirewallServiceCustom['SRVC22'] = {value:['1/any/any:','17/eq/any/eq/123;0/0'     ],protocol_type:PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_TCP_UDP_SCTP},comment:''
*   objFirewallServiceGroup['SRVCG11'] = {value:['58/any/any;-'                          ],protocol_type:PROTOCOL_TYPE_BIT_ICMP_ICMP6                               },comment:''
*   objFirewallServiceGroup['SRVCG21'] = {value:['1/any/any;-','6/eq/any/eq/80;0/0'      ],protocol_type:PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_TCP_UDP_SCTP},comment:''
*
*   objParam['member']                      objParam['comment']    Return['value']                                                                                                     Return['protocol_type']                                                          Return['comment']
*   -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   '"SRVC11"'                              'MyComment.'        -> ['1/any/any;-'                                                                                                    ] PROTOCOL_TYPE_BIT_ICMP_ICMP6                                                     'MyComment.'
*   '"SRVC11" "SRVC12'                      'My comment.'       -> ['1/any/any;-','6/eq/any/eq/80;0/0'                                                                               ] PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_TCP_UDP_SCTP                      'My comment.'
*   '"SRVC11" "SRVC12" "SRVC21" "SRVC22"'   ''                  -> ['1/any/any;-','6/eq/any/eq/80;0/0','ip;-','17/eq/any/eq/123;192.168.0.1/32','17/eq/any/eq/123;0/0'               ] PROTOCOL_TYPE_BIT_IP|PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_TCP_UDP_SCTP ''
*   '"SRVCG11"'                             'Comment'           -> ['58/any/any;-'                                                                                                   ] PROTOCOL_TYPE_BIT_ICMP_ICMP6                                                     'Comment'
*   '"SRVC21" "SRVC22" "SRVCG11" "SRVCG21"' 'Comment'           -> ['ip;-','17/eq/any/eq/123;192.168.0.1/32','1/any/any;-','17/eq/any/eq/123;0/0','58/any/any;-','6/eq/any/eq/80;0/0'] PROTOCOL_TYPE_BIT_IP|PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_TCP_UDP_SCTP 'Comment'
*   '"UNKNOWN"'                             'Comment'           -> [                                                                                                                 ] PROTOCOL_TYPE_BIT_NONE                                                           'Comment.'
*/
function normalizeFirewallServiceGroup(objParam, objFirewallServiceCustom, objFirewallServiceGroup) {
    const objReturn = {};
    const arrayValue = flattenMember(objFirewallServiceCustom, objParam['member']);
    arrayValue.push(...flattenMember(objFirewallServiceGroup, objParam['member']));
    objReturn['value'] = arrayValue.unique();
    objReturn['protocol_type'] = getProtocolTypeBitsOfArray(objReturn['value']);
    objReturn['comment'] = objParam['comment'];
    return objReturn;
}

/*
* ============================================================================
* Firewall Policy Normalization
*
* Firewall Policy Normalization normalizes all firewall policies to the
* following format.
*
*   DOM_NAME,S_INTF,D_INTF,POL_TYPE,POL_ID,POL_NAME,POL_LINE,{accept|deny|ipsec},PROT,S_ADDR,S_PORT,D_ADDR,D_PORT,SD_ADDR,I_TPCD,SA_NEGATE,DA_NEGATE,SV_NEGATE,{enable|disable},LOG,SCHEDULE,COMMENT
*
*     DOM_NAME     domain name
*     S_INTF       source interface
*     D_INTF       destination interface
*     POL_TYPE     policy type
*     POL_ID       policy id
*     POL_NAME     policy name
*     POL_LINE     policy line number
*     PROT         protocol service name
*     S_ADDR       source network address
*     S_PORT       source port service name
*     D_ADDR       destination network address
*     D_PORT       destination port service name
*     SD_ADDR      service destination address
*     I_TPCD       icmp-type and icmp-code service name
*     SA_NEGATE    true if source address negates
*     DA_NEGATE    true if destination address negates
*     SV_NEGATE    true if service negates
*     LOG          log
*     SCHEDULE     schedule name
*     COMMENT      comment
*
* This format is described as following rules.
*
*  - DOM_NAME, S_INTF, D_INTF, POL_ID, POL_NAME, SCHEDULE, and COMMENT are the
*    same as configuration. However, if S_INTF or D_INTF is two or more
*    interfaces, the policy is divided by the interfaces.
*
*  - POL_TYPE is one of the following.
*
*      4to4: IPv4 policy
*      6to6: IPv6 policy
*      4to6: IPv4 to IPv6 policy
*      6to4: IPv6 to IPv4 policy
*      4to4m: IPv4 multicast NAT policy
*      6to6m: IPv6 multicast NAT policy
*
*  - POL_LINE is the policy order number in policy type.
*
*  - In the non-multicast NAT policy, PROT, S_PORT, D_PORT, SD_ADDR, and
*    I_TPCD are described by the service object and service-group object name.
*    However, S_PORT and D_PORT are described as '-/-' and SD_ADDR is
*    described as '-' if the service object protocol is IP, ICMP, or ICMP6.
*    Likewise, I_TPCD is described as '-/-' if the service object protocol is
*    IP or TCP/UDP/SCTP protocol. In multicast NAT policy, these follow the
*    flattening rule.
*
*  - LOG is currently not supported. It is described as '-.'
*
* ============================================================================
*/

/**
* This function normalizes the policy of a policy object in the 'firewall
* policy', 'firewall policy6', 'firewall policy64', or 'firewall policy46'
* configuration and returns the array of normalized policy strings.
*
* @param {string} strDomainName - Domain name of the policy object.
* @param {string} strPolicyType - Policy type of the policy object.
* @param {string} strPolicyID - Policy id of the policy object.
* @param {number} intOrderNumber - Order number in the policy type.
* @param {Object} objParam - Parameter object of a policy object to normalize.
* @return {Array} Array of normalized policy strings.
*
* @example
*   Variables state when calls.
*   --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   objFirewallServiceCustom['SRVC12'] = {value:['1/any/any;-'                               ],protocol_type:PROTOCOL_TYPE_BIT_ICMP_ICMP6                               ,comment:''}
*   objFirewallServiceCustom['SRVC13'] = {value:['UNKNOWN;UNKNOWN'                           ],protocol_type:PROTOCOL_TYPE_BIT_UNSUPPORTED                              ,comment:''}
*   objFirewallServiceCustom['SRVC21'] = {value:['6/eq/any/eq/443;0/0','17/eq/any/eq/123;0/0'],protocol_type:PROTOCOL_TYPE_BIT_TCP_UDP_SCTP                             ,comment:''}
*   objFirewallServiceGroup['SRVCG11'] = {value:['58/any/any;-'                              ],protocol_type:PROTOCOL_TYPE_BIT_ICMP_ICMP6                               ,comment:''}
*   objFirewallServiceGroup['SRVCG21'] = {value:['1/any/any;-','6/eq/any/eq/80;0/0'          ],protocol_type:PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_TCP_UDP_SCTP,comment:''}
*
*                                                          objParam
*   strDomainName strPolicyType strPolicyID intOrderNumber ['srcaddr']          ['dstaddr']          ['service']          ['srcaddr_negate'] ['dstaddr_negate'] ['service_negate'] ['name']        ['action'] ['status'] ['srcintf']                 ['dstintf']       ['schedule'] ['comments']        Return
*   -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   'VDOM01'      '4to4'        '1234'      1              '"ADDR11" "ADDR12"'  '"ADDR21" "ADDR22"'  '"SRVC12" "SRVC21"'  'false'            'false'            'false'            'Policy name 1' 'deny'     'enable'   '"internal1" "INTERNAL 02"' '"wan2" "WAN 02"' 'Schedule 1' ''               -> ['VDOM01,internal1,wan2,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR11,-/-,ADDR21,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR11,SRVC21,ADDR21,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR11,-/-,ADDR22,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR11,SRVC21,ADDR22,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR12,-/-,ADDR21,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR12,SRVC21,ADDR21,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR12,-/-,ADDR22,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR12,SRVC21,ADDR22,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR11,-/-,ADDR21,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR11,SRVC21,ADDR21,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR11,-/-,ADDR22,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR11,SRVC21,ADDR22,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR12,-/-,ADDR21,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR12,SRVC21,ADDR21,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR12,-/-,ADDR22,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR12,SRVC21,ADDR22,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,wan2,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR11,-/-,ADDR21,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,wan2,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR11,SRVC21,ADDR21,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,wan2,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR11,-/-,ADDR22,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,wan2,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR11,SRVC21,ADDR22,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,wan2,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR12,-/-,ADDR21,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,wan2,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR12,SRVC21,ADDR21,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,wan2,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR12,-/-,ADDR22,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,wan2,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR12,SRVC21,ADDR22,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR11,-/-,ADDR21,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR11,SRVC21,ADDR21,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR11,-/-,ADDR22,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR11,SRVC21,ADDR22,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR12,-/-,ADDR21,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR12,SRVC21,ADDR21,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC12,ADDR12,-/-,ADDR22,-/-,-,SRVC12,false,false,false,enable,-,Schedule 1,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,INTERNAL 02,WAN 02,4to4,1234,Policy name 1,1,deny,SRVC21,ADDR12,SRVC21,ADDR22,SRVC21,SRVC21,-/-,false,false,false,enable,-,Schedule 1,']
*                                                          objParam
*   strDomainName strPolicyType strPolicyID intOrderNumber ['srcaddr']          ['dstaddr']          ['service']          ['srcaddr_negate'] ['dstaddr_negate'] ['service_negate'] ['name']        ['action'] ['status'] ['srcintf']                 ['dstintf']       ['schedule'] ['comments']        Return
*   ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   'VDOM01'      '6to6'        '1234'      1              '"ADDR11" "ADDRG11"' '"ADDR21" "ADDRG21"' '"SRVC12" "SRVCG21"' 'true'             'true'             'true'             ''              'accept'   'disable'  '"internal1"'               '"wan2"'          'always'     ''               -> ['VDOM01,internal1,wan2,6to6,1234,,1,accept,SRVC12,ADDR11,-/-,ADDR21,-/-,-,SRVC12,true,true,true,disable,-,always,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,6to6,1234,,1,accept,SRVCG21,ADDR11,SRVCG21,ADDR21,SRVCG21,SRVCG21,SRVCG21,true,true,true,disable,-,always,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,6to6,1234,,1,accept,SRVC12,ADDR11,-/-,ADDRG21,-/-,-,SRVC12,true,true,true,disable,-,always,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,6to6,1234,,1,accept,SRVCG21,ADDR11,SRVCG21,ADDRG21,SRVCG21,SRVCG21,SRVCG21,true,true,true,disable,-,always,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,6to6,1234,,1,accept,SRVC12,ADDRG11,-/-,ADDR21,-/-,-,SRVC12,true,true,true,disable,-,always,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,6to6,1234,,1,accept,SRVCG21,ADDRG11,SRVCG21,ADDR21,SRVCG21,SRVCG21,SRVCG21,true,true,true,disable,-,always,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,6to6,1234,,1,accept,SRVC12,ADDRG11,-/-,ADDRG21,-/-,-,SRVC12,true,true,true,disable,-,always,',
*                                                                                                                                                                                                                                                                                                       'VDOM01,internal1,wan2,6to6,1234,,1,accept,SRVCG21,ADDRG11,SRVCG21,ADDRG21,SRVCG21,SRVCG21,SRVCG21,true,true,true,disable,-,always,']
*                                                          objParam
*   strDomainName strPolicyType strPolicyID intOrderNumber ['srcaddr']          ['dstaddr']          ['service']          ['srcaddr_negate'] ['dstaddr_negate'] ['service_negate'] ['name']        ['action'] ['status'] ['srcintf']                 ['dstintf']       ['schedule'] ['comments']        Return
*   --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   ''            '6to4'        '1234'      1              '"ADDRG11"'          '"ADDR21"'           '"SRVCG11"'          '-'                '-'                '-'                '-'             ''         ''         '"internal1"'               '"wan2"'          'always'     ''               -> [',internal1,wan2,6to4,1234,-,1,deny,SRVCG11,ADDRG11,-/-,ADDR21,-/-,-,SRVCG11,-,-,-,enable,-,always,']
*   ''            '4to6'        '1234'      1              '"ADDR11"'           '"ADDRG21"'          '"SRVC13" "SRVC21"'  '-'                '-'                '-'                '-'             'ipsec'    ''         '"internal1"'               '"wan2"'          'always'     ''               -> [',internal1,wan2,4to6,1234,-,1,ipsec,SRVC13,ADDR11,SRVC13,ADDRG21,SRVC13,SRVC13,SRVC13,-,-,-,enable,-,always,',
*                                                                                                                                                                                                                                                                                                       ',internal1,wan2,4to6,1234,-,1,ipsec,SRVC21,ADDR11,SRVC21,ADDRG21,SRVC21,SRVC21,-/-,-,-,-,enable,-,always,']
*/
function normalizeFirewallPolicy(strDomainName, strPolicyType, strPolicyID, intOrderNumber, objParam) {
    const strName = objParam['name'].trimString('"').trimString('\'');
    const strStatus = objParam['status'] === '' ? 'enable' : objParam['status'];
    const strAction = objParam['action'] === '' ? 'deny' : objParam['action'];
    const strSchedule = objParam['schedule'].trimString('"').trimString('\'');
    const strComments = objParam['comments'].trimString('"').trimString('\'');
    const objFirewallServiceCustom = g_Domain_Data[strDomainName].service_custom;
    const objFirewallServiceGroup  = g_Domain_Data[strDomainName].service_group;

    const arraySrcIntf = [];
    const arrayDstIntf = [];
    const arraySrcAddr = [];
    const arrayDstAddr = [];
    const arrayService = [];
    if (objParam['srcintf'] !== '') {
        arraySrcIntf.push(...objParam['srcintf'].trimString('"').split('" "'));
    }
    if (objParam['dstintf'] !== '') {
        arrayDstIntf.push(...objParam['dstintf'].trimString('"').split('" "'));
    }
    if (objParam['srcaddr'] !== '') {
        arraySrcAddr.push(...objParam['srcaddr'].trimString('"').split('" "'));
    }
    if (objParam['dstaddr'] !== '') {
        arrayDstAddr.push(...objParam['dstaddr'].trimString('"').split('" "'));
    }
    if (objParam['service'] !== '') {
        arrayService.push(...objParam['service'].trimString('"').split('" "'));
    }

    const arrayReturn = [];
    let index = 0;
    for (let i=0; i<arraySrcIntf.length; ++i) {
        for (let j=0; j<arrayDstIntf.length; ++j) {
            for (let k=0; k<arraySrcAddr.length; ++k) {
                for (let l=0; l<arrayDstAddr.length; ++l) {
                    for (let m=0; m<arrayService.length; ++m) {
                        let strPort = '-/-';
                        let strTypeCode = '-/-';
                        if (objFirewallServiceCustom[arrayService[m]]) {
                            if (objFirewallServiceCustom[arrayService[m]].protocol_type & (PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_UNSUPPORTED)) {
                                strTypeCode = arrayService[m];
                            }
                            if (objFirewallServiceCustom[arrayService[m]].protocol_type & (PROTOCOL_TYPE_BIT_TCP_UDP_SCTP|PROTOCOL_TYPE_BIT_UNSUPPORTED)) {
                                strPort = arrayService[m];
                            }
                        } else if (objFirewallServiceGroup[arrayService[m]]) {
                            if (objFirewallServiceGroup[arrayService[m]].protocol_type & (PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_UNSUPPORTED)) {
                                strTypeCode = arrayService[m];
                            }
                            if (objFirewallServiceGroup[arrayService[m]].protocol_type & (PROTOCOL_TYPE_BIT_TCP_UDP_SCTP|PROTOCOL_TYPE_BIT_UNSUPPORTED)) {
                                strPort = arrayService[m];
                            }
                        } else { // Unknown service name.
                            strPort = arrayService[m];
                            strTypeCode = arrayService[m];
                        }
                        const strServiceDstAddr = strPort === '-/-' ? '-' : strPort;
                        arrayReturn[index++] =
                            strDomainName + ',' +
                            arraySrcIntf[i] + ',' +
                            arrayDstIntf[j] + ',' +
                            strPolicyType + ',' +
                            strPolicyID + ',' +
                            strName + ',' +
                            intOrderNumber + ',' +
                            strAction + ',' +
                            arrayService[m] + ',' +
                            arraySrcAddr[k] + ',' +
                            strPort + ',' +
                            arrayDstAddr[l] + ',' +
                            strPort + ',' +
                            strServiceDstAddr + ',' +
                            strTypeCode + ',' +
                            objParam['srcaddr_negate'] + ',' +
                            objParam['dstaddr_negate'] + ',' +
                            objParam['service_negate'] + ',' +
                            strStatus + ',' +
                            '-,' + // log.
                            strSchedule + ',' +
                            strComments;
                    }
                }
            }
        }
    }
    return arrayReturn;
}

/**
* This function normalizes the policy of a multicast policy object in the
* 'firewall multicast-policy' or 'firewall multicast-policy6' configuration
* and returns the array of normalized policy strings.
*
* @param {string} strDomainName - Domain name of the policy object.
* @param {string} strPolicyType - Policy type of the policy object.
* @param {string} strPolicyID - Policy id of the policy object.
* @param {number} intOrderNumber - Order number in the policy type.
* @param {Object} objParam -
*   Parameter object of a multicast policy object to normalize.
* @return {Array} Array of normalized policy strings.
*
* @example
*                                                          objParam
*   strDomainName strPolicyType strPolicyID intOrderNumber ['srcaddr']          ['dstaddr']                       ['protocol'] ['action'] ['status'] ['srcintf']   ['dstintf'] ['start-port'] ['end-port']    Return
*   --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   ''            '4to4m'       '1001'      1              '"ADDR11"'           '"MCAST-ADDR-01"'                 'ip'         'accept'   'enable'   '"internal1"' '"wan2"'    ''             ''           -> [',internal1,wan2,4to4m,1001,-,1,accept,ip,ADDR11,-/-,MCAST-ADDR-01,-/-,-,-/-,-,-,-,enable,-,-,-']
*   ''            '4to4m'       '1003'      3              '"ADDR21"'           '"MCAST-ADDR-01"'                 '1'          'accept'   'disable'  '"internal1"' '"wan2"'    ''             ''           -> [',internal1,wan2,4to4m,1003,-,3,accept,1,ADDR21,-/-,MCAST-ADDR-01,-/-,-,any/any,-,-,-,disable,-,-,-']
*   ''            '6to6m'       '1002'      2              '"ADDRG11"'          '"MCAST-ADDR 02"'                 '89'         'deny'     'disable'  '"internal1"' '"wan2"'    ''             ''           -> [',internal1,wan2,6to6m,1002,-,2,deny,89,ADDRG11,-/-,MCAST-ADDR 02,-/-,-,-/-,-,-,-,disable,-,-,-']
*   ''            '6to6m'       '1004'      4              '"ADDRG21"'          '"MCAST-ADDR-01"'                 '17'         'deny'     'enable'   '"internal1"' '"wan2"'    ''             ''           -> [',internal1,wan2,6to6m,1004,-,4,deny,17,ADDRG21,eq/any,MCAST-ADDR-01,eq/any,0/0,-/-,-,-,-,enable,-,-,-']
*   'VDOM01'      '4to4m'       '2001'      2              '"ADDR11"'           '"MCAST-ADDR-01"'                 '6'          'accept'   'enable'   '"internal2"' '"WAN 02"'  '1111'         ''           -> ['VDOM01,internal2,WAN 02,4to4m,2001,-,2,accept,6,ADDR11,eq/any,MCAST-ADDR-01,eq/1111,0/0,-/-,-,-,-,enable,-,-,-']
*   'VDOM01'      '6to6m'       '2002'      3              '"ADDR22" "ADDRG21"' '"MCAST-ADDR-01" "MCAST-ADDR 02"' '17'         'accept'   'enable'   '"internal2"' '"WAN 02"'  '1111'         '1119'       -> ['VDOM01,internal2,WAN 02,6to6m,2002,-,3,accept,17,ADDR22,eq/any,MCAST-ADDR-01,range/1111-1119,0/0,-/-,-,-,-,enable,-,-,-',
*                                                                                                                                                                                                              'VDOM01,internal2,WAN 02,6to6m,2002,-,3,accept,17,ADDR22,eq/any,MCAST-ADDR 02,range/1111-1119,0/0,-/-,-,-,-,enable,-,-,-',
*                                                                                                                                                                                                              'VDOM01,internal2,WAN 02,6to6m,2002,-,3,accept,17,ADDRG21,eq/any,MCAST-ADDR-01,range/1111-1119,0/0,-/-,-,-,-,enable,-,-,-',
*                                                                                                                                                                                                              'VDOM01,internal2,WAN 02,6to6m,2002,-,3,accept,17,ADDRG21,eq/any,MCAST-ADDR 02,range/1111-1119,0/0,-/-,-,-,-,enable,-,-,-']
*/
function normalizeFirewallMulticastPolicy(strDomainName, strPolicyType, strPolicyID, intOrderNumber, objParam) {
    const strStatus = objParam['status'] === '' ? 'enable' : objParam['status'];
    const strAction = objParam['action'] === '' ? 'accept' : objParam['action'];

    let strProtocol = objParam['protocol'];
    let strSrcPort = '-/-';
    let strDstPort = '-/-';
    let strTypeCode = '-/-';
    let strServiceDstAddr = '-';
    if (isIcmpProtocol(strProtocol) || isIcmp6Protocol(strProtocol)) {
        strTypeCode = 'any/any';
    } else if (isTcpProtocol(strProtocol) || isUdpProtocol(strProtocol) || isSctpProtocol(strProtocol)) {
        strSrcPort = 'eq/any';
        if (objParam['start_port'] === '') {
            strDstPort = 'eq/any';
        } else if (objParam['end_port'] === '') {
            strDstPort = 'eq/' + objParam['start_port'];
        } else {
            strDstPort = 'range/' + objParam['start_port'] + '-' + objParam['end_port'];
        }
        strServiceDstAddr = '0/0';
    } else if (strProtocol === '' || strProtocol === '0' || isIpProtocol(strProtocol)) {
        strProtocol = 'ip';
    } else if (Number.isInteger(+strProtocol)) {
        // as-is.
    } else { // Unknown.
        strSrcPort = strProtocol;
        strDstPort = strProtocol;
        strTypeCode = strProtocol;
    }

    const arraySrcIntf = [];
    const arrayDstIntf = [];
    const arraySrcAddr = [];
    const arrayDstAddr = [];
    if (objParam['srcintf'] !== '') {
        arraySrcIntf.push(...objParam['srcintf'].trimString('"').split('" "'));
    }
    if (objParam['dstintf'] !== '') {
        arrayDstIntf.push(...objParam['dstintf'].trimString('"').split('" "'));
    }
    if (objParam['srcaddr'] !== '') {
        arraySrcAddr.push(...objParam['srcaddr'].trimString('"').split('" "'));
    }
    if (objParam['dstaddr'] !== '') {
        arrayDstAddr.push(...objParam['dstaddr'].trimString('"').split('" "'));
    }

    const arrayReturn = [];
    let index = 0;
    for (let i=0; i<arraySrcIntf.length; ++i) {
        for (let j=0; j<arrayDstIntf.length; ++j) {
            for (let k=0; k<arraySrcAddr.length; ++k) {
                for (let l=0; l<arrayDstAddr.length; ++l) {
                    arrayReturn[index++] =
                        strDomainName + ',' +
                        arraySrcIntf[i] + ',' +
                        arrayDstIntf[j] + ',' +
                        strPolicyType + ',' +
                        strPolicyID + ',' +
                        '-,' + // policy name.
                        intOrderNumber + ',' +
                        strAction + ',' +
                        strProtocol + ',' +
                        arraySrcAddr[k] + ',' +
                        strSrcPort + ',' +
                        arrayDstAddr[l] + ',' +
                        strDstPort + ',' +
                        strServiceDstAddr + ',' +
                        strTypeCode + ',' +
                        '-,-,-,' +  // srcaddr negate, dstaddr negate, and service negate.
                        strStatus + ',' +
                        '-,' +  // log.
                        '-,-';  // schedule, comments.
                }
            }
        }
    }
    return arrayReturn;
}

/*
* ============================================================================
* ============================================================================
*/

/**
* This function initializes the domain data of specified domain name.
*
* @param {string} strDomainName - Domain name that to initialize data.
*
*/
function initDomainData(strDomainName) {
    g_Domain_Data[strDomainName] = {};
    g_Domain_Data[strDomainName].service_custom = {};
    g_Domain_Data[strDomainName].service_group  = {};
    g_Domain_Data[strDomainName].address4 = {};
    g_Domain_Data[strDomainName].addrgrp4 = {};
    g_Domain_Data[strDomainName].address6 = {};
    g_Domain_Data[strDomainName].addrgrp6 = {};
    g_Domain_Data[strDomainName].multicastaddress4 = {};
    g_Domain_Data[strDomainName].multicastaddress6 = {};
    g_Domain_Data[strDomainName].policy4to4 = [];
    g_Domain_Data[strDomainName].policy6to6 = [];
    g_Domain_Data[strDomainName].policy6to4 = [];
    g_Domain_Data[strDomainName].policy4to6 = [];
    g_Domain_Data[strDomainName].policy4to4m = [];
    g_Domain_Data[strDomainName].policy6to6m = [];
}

/**
* This function parses FortiGate configuration and saves the parsed result
* into g_Domain_Data. Configuration sections parsed are as follows.
*
*     config firewall address
*     config firewall multicast-address
*     config firewall address6
*     config firewall multicast-address6
*     config firewall addrgrp
*     config firewall addrgrp6
*     config firewall service custom
*     config firewall service group
*     config firewall policy
*     config firewall policy6
*     config firewall policy64
*     config firewall policy46
*     config firewall multicast-policy
*     config firewall multicast-policy6
*
* @param {string} configToFlat - FortiGate configuration that to parse.
*
* @example
*   configToFlat
*   -----------------------------------------------------
*   config vdom
*   edit VDOM01
*   config firewall address
*       edit "ADDR1001"
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set subnet 192.168.0.1 255.255.255.255
*       next
*       edit "ADDR1002"
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set subnet 10.0.0.0 255.0.0.0
*       next
*       edit "ADDR1003"
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set type iprange
*           set start-ip 172.16.0.1
*           set end-ip 172.16.0.100
*       next
*   end
*   config firewall multicast-address
*       edit "ADDR1001"
*           set start-ip 224.0.0.1
*           set end-ip 224.0.0.100
*       next
*   end
*   config firewall address6
*       edit "ADDR1001"
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set ip6 2001:db8::1/128
*       next
*       edit "ADDR1002"
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set ip6 2001:db8::/32
*       next
*       edit "ADDR1003"
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set type iprange
*           set start-ip 2001:db8:eeee:eeee::1
*           set end-ip 2001:db8:eeee:eeee::100
*       next
*   end
*   config firewall multicast-address6
*       edit "ADDR1001"
*           set ip6 ff00::/120
*       next
*   end
*   config firewall addrgrp
*       edit "ADDRG1001"
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set member "ADDR1002" "ADDR1003"
*       next
*   end
*   config firewall addrgrp6
*       edit "ADDRG1001"
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set member "ADDR1002" "ADDR1003"
*       next
*   end
*   config firewall service custom
*       edit "SRVC1001"
*           set protocol ICMP
*           unset icmptype
*       next
*       edit "SRVC1002"
*           set tcp-portrange 80
*       next
*   end
*   config firewall service group
*       edit "SRVCG1001"
*           set member "SRVC1001" "SRVC1002"
*       next
*   end
*   config firewall policy
*       edit 1001
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set srcintf "internal1"
*           set dstintf "wan2"
*           set srcaddr "ADDR1001"
*           set dstaddr "ADDRG1001"
*           set action accept
*           set schedule "always"
*           set service "SRVC1001"
*       next
*   end
*   config firewall policy6
*       edit 1001
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set srcintf "internal1" "INTERNAL 02"
*           set dstintf "wan2" "WAN 02"
*           set srcaddr "ADDR1001" "ADDR1002"
*           set dstaddr "ADDRG1001" "ADDR1003"
*           set action accept
*           set schedule "always"
*           set service "SRVCG1001" "SRVC1002"
*       next
*   end
*   config firewall policy64
*       edit 1001
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set srcintf "internal1"
*           set dstintf "wan2"
*           set srcaddr "ADDR1001"
*           set dstaddr "ADDRG1001"
*           set action accept
*           set schedule "always"
*           set service "SRVC1001"
*       next
*   end
*   config firewall policy46
*       edit 1001
*           set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
*           set srcintf "internal1"
*           set dstintf "wan2"
*           set srcaddr "ADDR1001"
*           set dstaddr "VIP1001"
*           set action accept
*           set schedule "always"
*           set service "SRVCG1001"
*       next
*   end
*   config firewall multicast-policy
*       edit 1001
*           set srcintf "internal1"
*           set dstintf "wan2"
*           set srcaddr "ADDR1001"
*           set dstaddr "ADDR1001"
*       next
*   end
*   config firewall multicast-policy6
*       edit 1001
*           set srcintf "internal1"
*           set dstintf "wan2"
*           set srcaddr "ADDR1001"
*           set dstaddr "ADDR1001"
*           set protocol 17
*           set start-port 10001
*           set end-port 10009
*       next
*   end
*   end
*
*      Results of g_Domain_Data
*   ----------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   -> g_Domain_Data['VDOM01'].address4 = {
*          'ADDR1001':{value:['192.168.0.1/32'],comment:''},
*          'ADDR1002':{value:['10.0.0.0/8'],comment:''},
*          'ADDR1003':{value:['172.16.0.1-172.16.0.100'],comment:''}
*      }
*      g_Domain_Data['VDOM01'].address6 = {
*          'ADDR1001':{value:['2001:0db8:0000:0000:0000:0000:0000:0001/128'],comment:''},
*          'ADDR1002':{value:['2001:0db8:0000:0000:0000:0000:0000:0000/32'],comment:''},
*          'ADDR1003':{value:['2001:0db8:eeee:eeee:0000:0000:0000:0001-2001:0db8:eeee:eeee:0000:0000:0000:0100'],comment:''}
*      }
*      g_Domain_Data['VDOM01'].addrgrp4 = {
*          'ADDRG1001':{value:['10.0.0.0/8','172.16.0.1-172.16.0.100'],comment:''}
*      }
*      g_Domain_Data['VDOM01'].addrgrp6 = {
*          'ADDRG1001':{value:['2001:0db8:0000:0000:0000:0000:0000:0000/32','2001:0db8:eeee:eeee:0000:0000:0000:0001-2001:0db8:eeee:eeee:0000:0000:0000:0100'],comment:''}
*      }
*      g_Domain_Data['VDOM01'].multicast_address4 = {
*          'ADDR1001':{value:['224.0.0.1-224.0.0.100'],comment:''}
*      }
*      g_Domain_Data['VDOM01'].multicast_address6 = {
*          'ADDR1001':{value:['ff00:0000:0000:0000:0000:0000:0000:0000/120'],comment:''}
*      }
*      g_Domain_Data['VDOM01'].service_custom = {
*          'SRVC1001':{value:['1/any/any;-'],protocol_type:PROTOCOL_TYPE_BIT_ICMP_ICMP6,comment:''},
*          'SRVC1002':{value:['6/eq/any/eq/80;0/0'],protocol_type:PROTOCOL_TYPE_BIT_TCP_UDP_SCTP,comment:''}
*      }
*      g_Domain_Data['VDOM01'].service_group = {
*          'SRVCG1001':{value:['1/any/any;-','6/eq/any/eq/80;0/0'],protocol_type:PROTOCOL_TYPE_BIT_ICMP_ICMP6|PROTOCOL_TYPE_BIT_TCP_UDP_SCTP,comment:''}
*      }
*      g_Domain_Data['VDOM01'].policy4to4 = [
*          'VDOM01,internal1,wan2,4to4,1001,,1,accept,SRVC1001,ADDR1001,-/-,ADDRG1001,-/-,-,SRVC1001,false,false,false,enable,-,always,'
*      ]
*      g_Domain_Data['VDOM01'].policy6to6 = [
*          'VDOM01,internal1,wan2,6to6,1001,,1,accept,SRVCG1001,ADDR1001,SRVCG1001,ADDRG1001,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,internal1,wan2,6to6,1001,,1,accept,SRVC1002,ADDR1001,SRVC1002,ADDRG1001,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,internal1,wan2,6to6,1001,,1,accept,SRVCG1001,ADDR1001,SRVCG1001,ADDR1003,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,internal1,wan2,6to6,1001,,1,accept,SRVC1002,ADDR1001,SRVC1002,ADDR1003,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,internal1,wan2,6to6,1001,,1,accept,SRVCG1001,ADDR1002,SRVCG1001,ADDRG1001,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,internal1,wan2,6to6,1001,,1,accept,SRVC1002,ADDR1002,SRVC1002,ADDRG1001,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,internal1,wan2,6to6,1001,,1,accept,SRVCG1001,ADDR1002,SRVCG1001,ADDR1003,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,internal1,wan2,6to6,1001,,1,accept,SRVC1002,ADDR1002,SRVC1002,ADDR1003,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,internal1,WAN 02,6to6,1001,,1,accept,SRVCG1001,ADDR1001,SRVCG1001,ADDRG1001,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,internal1,WAN 02,6to6,1001,,1,accept,SRVC1002,ADDR1001,SRVC1002,ADDRG1001,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,internal1,WAN 02,6to6,1001,,1,accept,SRVCG1001,ADDR1001,SRVCG1001,ADDR1003,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,internal1,WAN 02,6to6,1001,,1,accept,SRVC1002,ADDR1001,SRVC1002,ADDR1003,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,internal1,WAN 02,6to6,1001,,1,accept,SRVCG1001,ADDR1002,SRVCG1001,ADDRG1001,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,internal1,WAN 02,6to6,1001,,1,accept,SRVC1002,ADDR1002,SRVC1002,ADDRG1001,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,internal1,WAN 02,6to6,1001,,1,accept,SRVCG1001,ADDR1002,SRVCG1001,ADDR1003,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,internal1,WAN 02,6to6,1001,,1,accept,SRVC1002,ADDR1002,SRVC1002,ADDR1003,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,wan2,6to6,1001,,1,accept,SRVCG1001,ADDR1001,SRVCG1001,ADDRG1001,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,wan2,6to6,1001,,1,accept,SRVC1002,ADDR1001,SRVC1002,ADDRG1001,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,wan2,6to6,1001,,1,accept,SRVCG1001,ADDR1001,SRVCG1001,ADDR1003,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,wan2,6to6,1001,,1,accept,SRVC1002,ADDR1001,SRVC1002,ADDR1003,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,wan2,6to6,1001,,1,accept,SRVCG1001,ADDR1002,SRVCG1001,ADDRG1001,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,wan2,6to6,1001,,1,accept,SRVC1002,ADDR1002,SRVC1002,ADDRG1001,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,wan2,6to6,1001,,1,accept,SRVCG1001,ADDR1002,SRVCG1001,ADDR1003,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,wan2,6to6,1001,,1,accept,SRVC1002,ADDR1002,SRVC1002,ADDR1003,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,WAN 02,6to6,1001,,1,accept,SRVCG1001,ADDR1001,SRVCG1001,ADDRG1001,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,WAN 02,6to6,1001,,1,accept,SRVC1002,ADDR1001,SRVC1002,ADDRG1001,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,WAN 02,6to6,1001,,1,accept,SRVCG1001,ADDR1001,SRVCG1001,ADDR1003,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,WAN 02,6to6,1001,,1,accept,SRVC1002,ADDR1001,SRVC1002,ADDR1003,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,WAN 02,6to6,1001,,1,accept,SRVCG1001,ADDR1002,SRVCG1001,ADDRG1001,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,WAN 02,6to6,1001,,1,accept,SRVC1002,ADDR1002,SRVC1002,ADDRG1001,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,WAN 02,6to6,1001,,1,accept,SRVCG1001,ADDR1002,SRVCG1001,ADDR1003,SRVCG1001,SRVCG1001,SRVCG1001,false,false,false,enable,-,always,',
*          'VDOM01,INTERNAL 02,WAN 02,6to6,1001,,1,accept,SRVC1002,ADDR1002,SRVC1002,ADDR1003,SRVC1002,SRVC1002,-/-,false,false,false,enable,-,always,'
*      ]
*      g_Domain_Data['VDOM01'].policy6to4 = [
*          'VDOM01,internal1,wan2,6to4,1001,-,1,accept,SRVC1001,ADDR1001,-/-,ADDRG1001,-/-,-,SRVC1001,-,-,-,enable,-,always,'
*      ]
*      g_Domain_Data['VDOM01'].policy4to6 = [
*          'VDOM01,internal1,wan2,4to6,1001,-,1,accept,SRVCG1001,ADDR1001,SRVCG1001,VIP1001,SRVCG1001,SRVCG1001,SRVCG1001,-,-,-,enable,-,always,'
*      ]
*      g_Domain_Data['VDOM01'].policy4to4m = [
*          'VDOM01,internal1,wan2,4to4m,1001,-,1,accept,ip,ADDR1001,-/-,ADDR1001,-/-,-,-/-,-,-,-,enable,-,-,-'
*      ]
*      g_Domain_Data['VDOM01'].policy6to6m = [
*          'VDOM01,internal1,wan2,6to6m,1001,-,1,accept,17,ADDR1001,eq/any,ADDR1001,range/10001-10009,0/0,-/-,-,-,-,enable,-,-,-'
*      ]
*/
function parseFortiGateConfig(configToFlat) {
    const arrayText = configToFlat.split(/\r\n|\r|\n/);
    const stack_config = [];
    let strDomainName = '';
    let strEditName = '';
    let configEdit;

    for (let i=0; i<arrayText.length; ++i) {
        // Trim a line feed at the tail and trim white spaces at both head and tail.
        const strLine = arrayText[i].trim();

        // Skip if white line.
        if (strLine.length == 0) {
            continue;
        }

        // Skip if comment line.
        if (strLine.startsWith('#')) {
            continue;
        }

        //
        if (strLine === 'end') {
            const arrayPopped = stack_config.pop();
            if (arrayPopped[0] && arrayPopped[0] === 'config') {
                if (arrayPopped[1] && arrayPopped[1] === 'vdom') {
                    strDomainName = '';
                } else if (arrayPopped[2] && arrayPopped[1] === 'firewall') {
                    const strConfigName = arrayPopped[3] ? arrayPopped[2] + '_' + arrayPopped[3] : arrayPopped[2];
                    if (t_FortiGateFirewallObject[strConfigName]) {
                        strEditName = '';
                        configEdit.init();
                    }
                }
            }
            continue;
        }

        //
        if (strLine === 'next') {
            if (strEditName !== '') {
                configEdit.end();
                strEditName = '';
            }
            continue;
        }

        // Split by whitespace.
        const arrayToken = strLine.split(/\s+/);

        //
        if (arrayToken[0] && arrayToken[0] === 'config') {
            stack_config.push(arrayToken);
            continue;
        }

        //
        if (arrayToken[1] && arrayToken[0] === 'edit') {
            const arrayLast = stack_config.last();
            if (arrayLast[0] && arrayLast[0] === 'config') {
                if (arrayLast[1] && arrayLast[1] === 'vdom') {
                    strDomainName = strLine.substring(5).trimString('"'); // virtual domain name.
                    if (!g_Domain_Data[strDomainName]) {
                        initDomainData(strDomainName);
                    }
                } else if (arrayLast[2] && arrayLast[1] === 'firewall') {
                    const strConfigName = arrayLast[3] ? arrayLast[2] + '_' + arrayLast[3] : arrayLast[2];
                    if (t_FortiGateFirewallObject[strConfigName]) {
                        // Associate an object if 'edit vdom_name' line is not found.
                        if (!g_Domain_Data[strDomainName]) {
                            initDomainData('');
                        }
                        //
                        strEditName = strLine.substring(5).trimString('"');
                        configEdit = t_FortiGateFirewallObject[strConfigName];
                        configEdit.DomainName = strDomainName;
                        configEdit.begin(strEditName);
                    }
                }
            }
            continue;
        }

        //
        if (strEditName !== '') {
            if (arrayToken[0] && arrayToken[0] === 'set') {
                configEdit.set(strLine, arrayToken);
            }
        }
    }
}

/*
* ============================================================================
* Policy flattener
* ============================================================================
*/
/*
* ============================================================================
* Firewall Policy Flattening
*
* Firewall Policy Flattening flattens all firewall policies to the following
* format.
*
*  - PROT format is the following. If the protocol number is '0', it is
*    changed to 'ip.'
*
*      'NN'
*      NN: protocol-number or 'ip'
*
*  - S_PORT and D_PORT format is the following. If PROT is '6'(tcp), '17'(udp),
*    or '132'(sctp) and the port condition is not specified, S_PORT is
*    described as 'eq/any'. If PROT is neither '6', '17', nor '58', S_PORT and
*    D_PORT are described as '-/-'.
*
*      'eq/NN'
*      'range/SN-EN'
*      NN: port-number or 'any'
*      SN: start port-number
*      EN: end port-number
*
*  - I_TPCD format is the following. If icmp-type or icmp-code is not
*    specified explicitly, it is described as 'any'. If PROT is not '1'(icmp)
*    and '58'(icmp6), I_TPCD is described as '-/-'.
*
*      'TN/CN'
*      TN: icmp-type number or 'any'
*      CN: icmp-code number or 'any'
*
*  - S_ADDR and D_ADDR are CIDR representations if the network address is host
*    or subnet address. IPv6 address is adapted to the full represented. If
*    the network address is a range, S_ADDR and D_ADDR are not CIDR
*    representations. Its address is described in start-address, a hyphen,
*    end-address as following.
*
*      IPv4: 'x.x.x.x-y.y.y.y'
*      IPv6: 'xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx-yyyy:yyyy:yyyy:yyyy:yyyy:yyyy:yyyy:yyyy'
*
*    Also, if the network address is a wildcard address, its address is
*    described in IPv4 address, a slash, IPv4 wildcard mask, as following.
*
*      IPv4: 'x.x.x.x/m.m.m.m'
*
*    If the network address is FQDN, S_ADDR and D_ADDR are described as FQDN
*    with the prefix is 'fqdn:'. If the network address is geography, S_ADDR
*    and D_ADDR are described as the country name with the prefix is 'geo:'.
*
*    'all' network address is converted as following rules.
*
*      IPv4: '0.0.0.0/0'
*      IPv6: '0000:0000:0000:0000:0000:0000:0000:0000/0'
*
*  - SD_ADDR is the CIDR representation if the service destination address is
*    a host address. If the service destination address is a range, it is
*    described in start-address, a hyphen, end-address. Its prefix is 'fqdn:'
*    when FQDN. It is described as '0/0' if the service destination address is
*    '0.0.0.0.' If PROT is neither '6', '17', nor '58', SD_ADDR is described
*    as '-'.
*
* ============================================================================
*/

/**
* This function returns the address strings array of normalized policy.
*
* @param {Array} arrayToken - Tokens array of normalized policy.
* @param {number} index - Column index that to retrieve the address.
* @return {Array} Array of address strings.
*
* @example
*   Variables state when calls.
*   ------------------------------------------------------------------------------------------------------------------------------------------------------------
*   g_Domain_Data[''].address4['ADDR1'] = {value:['192.168.0.1/32'], comment:''}
*   g_Domain_Data[''].address4['ADDR2'] = {value:['192.168.0.2/32'], comment:''}
*   g_Domain_Data[''].addrgrp6['ADDRG1'] = {value:['2001:0db8:0000:0000:0000:0000:0000:0001/128','2001:0db8:0002:0003:0000:0000:0000:0000/64'], comment:''}
*   g_Domain_Data[''].addrgrp6['ADDRG2'] = {value:['2001:0db8:0000:0000:0000:0000:0000:0002/128','2001:0db8:0000:0000:0000:0000:0000:0000/16'], comment:''}
*   g_Domain_Data['VDOM1'].address4['ADDR1'] = {value:['192.168.1.1/32'], comment:''}
*   g_Domain_Data['VDOM1'].addrgrp4['ADDRG2'] = {value:['192.168.1.2/32','172.16.0.0/16' ], comment:''}
*   g_Domain_Data['VDOM1'].address6['ADDR2'] = {value:['2001:0db8:1000:0000:0000:0000:0000:0002/128'], comment:''}
*   g_Domain_Data['VDOM1'].addrgrp6['ADDRG1'] = {value:['2001:0db8:1000:0000:0000:0000:0000:0001/128','2001:0db8:1002:0003:0000:0000:0000:0000/64'], comment:''}
*
*   arrayToken                                                                                                                                                   index             Return
*   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   [''     ,'internal1','wan2','4to4','1234','' ,'1','deny','SRVC1','ADDR1' ,'-/-','ADDR2' ,'-/-','-','SRVC1','false','false','false','enable','-','always',''] NMCOL_SRC_ADDR -> ['192.168.0.1/32']
*   [''     ,'internal1','wan2','6to6','1234','' ,'1','deny','SRVC1','ADDRG1','-/-','ADDRG2','-/-','-','SRVC1','false','false','false','enable','-','always',''] NMCOL_DST_ADDR -> ['2001:0db8:0000:0000:0000:0000:0000:0002/128','2001:0db8:0000:0000:0000:0000:0000:0000/16']
*   ['VDOM1','internal1','wan2','4to6','1234','-','1','deny','SRVC1','ADDR1' ,'-/-','ADDR2' ,'-/-','-','SRVC1','-'    ,'-'    ,'-'    ,'enable','-','always',''] NMCOL_DST_ADDR -> ['2001:0db8:1000:0000:0000:0000:0000:0002/128']
*   ['VDOM1','internal1','wan2','6to4','1234','-','1','deny','SRVC1','ADDRG1','-/-','ADDRG2','-/-','-','SRVC1','-'    ,'-'    ,'-'    ,'enable','-','always',''] NMCOL_SRC_ADDR -> ['2001:0db8:1000:0000:0000:0000:0000:0001/128','2001:0db8:1002:0003:0000:0000:0000:0000/64']
*   []                                                                                                                                                           NMCOL_DST_ADDR -> []
*/
function getAddressArray(arrayToken, index) {
    const array = [];
    if (arrayToken[index]) {
        const objDomain = g_Domain_Data[arrayToken[NMCOL_DOM_NAME]];
        const strAddressOrAddressGroupName = arrayToken[index];

        const intPolicyType = t_FortiGatePolicyType[arrayToken[NMCOL_POL_TYPE]];
        const is4to4 = intPolicyType == POLICY_TYPE_4TO4;
        const is6to6 = intPolicyType == POLICY_TYPE_6TO6;
        const is6to4 = intPolicyType == POLICY_TYPE_6TO4;
        const is4to6 = intPolicyType == POLICY_TYPE_4TO6;
        const is4to4m = intPolicyType == POLICY_TYPE_4TO4M;
        const is6to6m = intPolicyType == POLICY_TYPE_6TO6M;
        const isSrcAddr = index == NMCOL_SRC_ADDR;
        const isDstAddr = index == NMCOL_DST_ADDR;

        if (((is4to4 || is4to6 || is4to4m) && isSrcAddr) || ((is4to4 || is6to4) && isDstAddr)) {
            const objFirewallAddressIPv4      = objDomain['address4'];
            const objFirewallAddressIPv4Group = objDomain['addrgrp4'];

            if (objFirewallAddressIPv4[strAddressOrAddressGroupName]) {
                array.push(...flattenMember(objFirewallAddressIPv4, strAddressOrAddressGroupName));
            } else if (objFirewallAddressIPv4Group[strAddressOrAddressGroupName]) {
                array.push(...flattenMember(objFirewallAddressIPv4Group, strAddressOrAddressGroupName));
            } else {
                array.push(strAddressOrAddressGroupName);
            }
        }
        if (((is6to6 || is6to4 || is6to6m) && isSrcAddr) || ((is6to6 || is4to6) && isDstAddr)) {
            const objFirewallAddressIPv6      = objDomain['address6'];
            const objFirewallAddressIPv6Group = objDomain['addrgrp6'];

            if (objFirewallAddressIPv6[strAddressOrAddressGroupName]) {
                array.push(...flattenMember(objFirewallAddressIPv6, strAddressOrAddressGroupName));
            } else if (objFirewallAddressIPv6Group[strAddressOrAddressGroupName]) {
                array.push(...flattenMember(objFirewallAddressIPv6Group, strAddressOrAddressGroupName));
            } else {
                array.push(strAddressOrAddressGroupName);
            }
        }
        if (is4to4m && isDstAddr) {
            const objFirewallMulticastAddressIPv4 = objDomain['multicastaddress4'];

            if (objFirewallMulticastAddressIPv4[strAddressOrAddressGroupName]) {
                array.push(...flattenMember(objFirewallMulticastAddressIPv4, strAddressOrAddressGroupName));
            } else {
                array.push(strAddressOrAddressGroupName);
            }
        }
        if (is6to6m && isDstAddr) {
            const objFirewallMulticastAddressIPv6 = objDomain['multicastaddress6'];

            if (objFirewallMulticastAddressIPv6[strAddressOrAddressGroupName]) {
                array.push(...flattenMember(objFirewallMulticastAddressIPv6, strAddressOrAddressGroupName));
            } else {
                array.push(strAddressOrAddressGroupName);
            }
        }
    }
    return array;
}

/**
* This function returns the service strings array of normalized policy.
*
* @param {Array} arrayToken - Tokens array of normalized policy.
* @return {Array} Array of service strings.
*
* @example
*   Variables state when calls.
*   -----------------------------------------------------------------------------------------------------------
*   g_Domain_Data[''].service_custom['SRVC1'] = {value:['ip;-'], comment:''}
*   g_Domain_Data[''].service_group['SRVCG3'] = {value:['1/any/any;-','6/eq/any/eq/80;0/0'], comment:''}
*   g_Domain_Data['VDOM1'].service_group['SRVCG3'] = {value:['58/any/any;-','6/eq/any/eq/443;0/0'], comment:''}
*
*   arrayToken                                                                                                                                                                       Return
*   -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   [''     ,'internal1','wan2','4to4' ,'1234','' ,'1','deny','SRVC1'  ,'ADDR1','-/-'    ,'ADDR2','-/-'    ,'-'      ,'-/-'    ,'false','false','false','enable','-','always',''] -> ['ip;-']
*   [''     ,'internal1','wan2','4to4' ,'1234','' ,'1','deny','SRVCG3' ,'ADDR1','SRVCG3' ,'ADDR2','SRVCG3' ,'SRVCG3' ,'SRVCG3' ,'false','false','false','enable','-','always',''] -> ['1/any/any;-','6/eq/any/eq/80;0/0']
*   ['VDOM1','internal1','wan2','4to4' ,'1234','' ,'1','deny','SRVCG3' ,'ADDR1','SRVCG3' ,'ADDR2','SRVCG3' ,'SRVCG3' ,'SRVCG3' ,'false','false','false','enable','-','always',''] -> ['58/any/any;-','6/eq/any/eq/443;0/0']
*   [''     ,'internal1','wan2','4to4m','1234','-','1','deny','6'      ,'ADDR1','eq/any' ,'ADDR2','eq/any','0/0'     ,'-/-'    ,'-'    ,'-'    ,'-'    ,'enable','-','-'     ,''] -> ['6/eq/any/eq/any;0/0']
*   []                                                                                                                                                                            -> []
*/
function getServiceArray(arrayToken) {
    const array = [];
    if (arrayToken[NMCOL_PROTOCOL]) {
        const objFirewallServiceCustom = g_Domain_Data[arrayToken[NMCOL_DOM_NAME]]['service_custom'];
        const objFirewallServiceGroup = g_Domain_Data[arrayToken[NMCOL_DOM_NAME]]['service_group'];
        const strProtocol = arrayToken[NMCOL_PROTOCOL];

        if (objFirewallServiceCustom[strProtocol]) {
            array.push(...flattenMember(objFirewallServiceCustom, strProtocol));
        } else if (objFirewallServiceGroup[strProtocol]) {
            array.push(...flattenMember(objFirewallServiceGroup, strProtocol));
        } else if (isIcmpProtocol(strProtocol) || isIcmp6Protocol(strProtocol)) { // ICMP or ICMP6 of multicast policy.
            array.push(strProtocol + '/' + arrayToken[NMCOL_ICMPTYCD] + ';' + arrayToken[NMCOL_SERVICE_DSTADDR]);
        } else if (isTcpProtocol(strProtocol) || isUdpProtocol(strProtocol) || isSctpProtocol(strProtocol)) { // TCP, UDP, or SCTP of multicast policy.
            array.push(strProtocol + '/' + arrayToken[NMCOL_SRC_PORT] + '/' + arrayToken[NMCOL_DST_PORT] + ';' + arrayToken[NMCOL_SERVICE_DSTADDR]);
        } else if (isIpProtocol(strProtocol) || Number.isInteger(+strProtocol)) { // IP of multicast policy.
            array.push(strProtocol + ';' + arrayToken[NMCOL_SERVICE_DSTADDR]);
        } else { // Unknown.
            array.push(strProtocol + ';' + arrayToken[NMCOL_SERVICE_DSTADDR]);
        }
    }
    return array;
}

/**
* This function flattens the address objects and address-group objects of
* normalized policy and returns the strings array of flattened policy.
*
* @param {Array} arrayToken - Tokens array of normalized policy.
* @return {Array} Strings array of flattened policy.
*
* @example
*   Variables state when calls.
*   ------------------------------------------------------------------------------------------------------------------------------------------------------------
*   g_Domain_Data[''].address4['ADDR1' ] = {value:['192.168.0.1/32'], comment:''}
*   g_Domain_Data[''].address4['ADDR2' ] = {value:['192.168.0.2/32'], comment:''}
*   g_Domain_Data[''].addrgrp4['ADDRG1'] = {value:['192.168.0.1/32','192.168.0.0/24'], comment:''}
*   g_Domain_Data[''].addrgrp6['ADDRG2'] = {value:['2001:0db8:0000:0000:0000:0000:0000:0002/128','2001:0db8:0000:0000:0000:0000:0000:0000/16'], comment:''}
*   g_Domain_Data['VDOM1'].address4['ADDR2' ] = {value:['192.168.1.2/32'], comment:''}
*   g_Domain_Data['VDOM1'].address6['ADDR1' ] = {value:['2001:0db8:1000:0000:0000:0000:0000:0001/128'], comment:''}
*   g_Domain_Data['VDOM1'].addrgrp6['ADDRG1'] = {value:['2001:0db8:1000:0000:0000:0000:0000:0001/128','2001:0db8:1002:0003:0000:0000:0000:0000/64'], comment:''}
*   g_Domain_Data['VDOM1'].addrgrp6['ADDRG2'] = {value:['2001:0db8:1000:0000:0000:0000:0000:0002/128','2001:0db8:1000:0000:0000:0000:0000:0000/16'], comment:''}
*
*   arrayToken                                                                                                                                                         Return
*   --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   [''     ,'internal1','wan2','4to4','1234','','1','deny','SRVC1','ADDR1'   ,'-/-','ADDR2'   ,'-/-','-','SRVC1','false','false','false','enable','-','always',''] -> [',internal1,wan2,4to4,1234,,1,deny,SRVC1,192.168.0.1/32,-/-,192.168.0.2/32,-/-,-,SRVC1,false,false,false,enable,-,always,']
*   [''     ,'internal1','wan2','4to6','1234','','1','deny','SRVC1','ADDRG1'  ,'-/-','ADDRG2'  ,'-/-','-','SRVC1','-'    ,'-'    ,'-'    ,'enable','-','always',''] -> [',internal1,wan2,4to6,1234,,1,deny,SRVC1,192.168.0.1/32,-/-,2001:0db8:0000:0000:0000:0000:0000:0002/128,-/-,-,SRVC1,-,-,-,enable,-,always,',
*                                                                                                                                                                       ',internal1,wan2,4to6,1234,,1,deny,SRVC1,192.168.0.1/32,-/-,2001:0db8:0000:0000:0000:0000:0000:0000/16,-/-,-,SRVC1,-,-,-,enable,-,always,',
*                                                                                                                                                                       ',internal1,wan2,4to6,1234,,1,deny,SRVC1,192.168.0.0/24,-/-,2001:0db8:0000:0000:0000:0000:0000:0002/128,-/-,-,SRVC1,-,-,-,enable,-,always,',
*                                                                                                                                                                       ',internal1,wan2,4to6,1234,,1,deny,SRVC1,192.168.0.0/24,-/-,2001:0db8:0000:0000:0000:0000:0000:0000/16,-/-,-,SRVC1,-,-,-,enable,-,always,']
*   ['VDOM1','internal1','wan2','6to4','1234','','1','deny','SRVC1','ADDR1'   ,'-/-','ADDR2'   ,'-/-','-','SRVC1','-'    ,'-'    ,'-'    ,'enable','-','always',''] -> ['VDOM1,internal1,wan2,6to4,1234,,1,deny,SRVC1,2001:0db8:1000:0000:0000:0000:0000:0001/128,-/-,192.168.1.2/32,-/-,-,SRVC1,-,-,-,enable,-,always,']
*   ['VDOM1','internal1','wan2','6to6','1234','','1','deny','SRVC1','ADDRG1'  ,'-/-','ADDRG2'  ,'-/-','-','SRVC1','false','false','false','enable','-','always',''] -> ['VDOM1,internal1,wan2,6to6,1234,,1,deny,SRVC1,2001:0db8:1000:0000:0000:0000:0000:0001/128,-/-,2001:0db8:1000:0000:0000:0000:0000:0002/128,-/-,-,SRVC1,false,false,false,enable,-,always,',
*                                                                                                                                                                       'VDOM1,internal1,wan2,6to6,1234,,1,deny,SRVC1,2001:0db8:1000:0000:0000:0000:0000:0001/128,-/-,2001:0db8:1000:0000:0000:0000:0000:0000/16,-/-,-,SRVC1,false,false,false,enable,-,always,',
*                                                                                                                                                                       'VDOM1,internal1,wan2,6to6,1234,,1,deny,SRVC1,2001:0db8:1002:0003:0000:0000:0000:0000/64,-/-,2001:0db8:1000:0000:0000:0000:0000:0002/128,-/-,-,SRVC1,false,false,false,enable,-,always,',
*                                                                                                                                                                       'VDOM1,internal1,wan2,6to6,1234,,1,deny,SRVC1,2001:0db8:1002:0003:0000:0000:0000:0000/64,-/-,2001:0db8:1000:0000:0000:0000:0000:0000/16,-/-,-,SRVC1,false,false,false,enable,-,always,']
*   ['VDOM1','internal1','wan2','6to6','1234','','1','deny','SRVC1','UNKNOWN1','-/-','UNKNOWN2','-/-','-','SRVC1','false','false','false','enable','-','always',''] -> ['VDOM1,internal1,wan2,6to6,1234,,1,deny,SRVC1,UNKNOWN1,-/-,UNKNOWN2,-/-,-,SRVC1,false,false,false,enable,-,always,']
*   []                                                                                                                                                              -> []
*/
const funcFlattenAddressAndAddressGroupOfNormalizedPolicy = function(arrayToken) {
    const arrayFlatString = [];
    const arraySrcIP = getAddressArray(arrayToken, NMCOL_SRC_ADDR);
    const arrayDstIP = getAddressArray(arrayToken, NMCOL_DST_ADDR);

    if (arraySrcIP[0] && arrayDstIP[0]) {
        let index = 0;
        for (let i=0; i<arraySrcIP.length; ++i) {
            for (let j=0; j<arrayDstIP.length; ++j) {
                arrayFlatString[index] = arrayToken[NMCOL_DOM_NAME];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_SRC_INTF];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_DST_INTF];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_POL_TYPE];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_POL_ID];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_POL_NAME];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_POL_LINE];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_ACTION];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_PROTOCOL];
                arrayFlatString[index] += ',' + arraySrcIP[i];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_SRC_PORT];
                arrayFlatString[index] += ',' + arrayDstIP[j];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_DST_PORT];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_SERVICE_DSTADDR];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_ICMPTYCD];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_SRCADDR_NEGATE];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_DSTADDR_NEGATE];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_SERVICE_NEGATE];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_STATUS];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_LOG];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_SCHEDULE];
                arrayFlatString[index] += ',' + arrayToken[NMCOL_COMMENT];
                ++index;
            }
        }
    }
    return arrayFlatString;
};

/**
* This function flattens the service objects and service-group objects of
* normalized policy and returns the strings array of flattened policy.
*
* @param {Array} arrayToken - Tokens array of normalized policy.
* @return {Array} Strings array of flattened policy.

* @example
*   Variables state when calls.
*   ------------------------------------------------------------------------------------------------------------------
*   g_Domain_Data[''].service_custom['SRVC1'] = {value:['ip;-'], comment:''}
*   g_Domain_Data[''].service_custom['SRVC13'] = {value:['6/eq/any/eq/443;192.168.0.1/32'], comment:''}
*   g_Domain_Data['VDOM1'].service_group['SRVCG4'] = {value:['89;-','58/any/any;-','6/eq/any/eq/443;0/0'], comment:''}
*
*   arrayToken                                                                                                                                                                       Return
*   ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   [''     ,'internal1','wan2','4to4' ,'1234','' ,'1','deny','SRVC1'  ,'ADDR1','-/-'    ,'ADDR2','-/-'    ,'-'      ,'-/-'    ,'false','false','false','enable','-','always',''] -> [',internal1,wan2,4to4,1234,,1,deny,ip,ADDR1,-/-,ADDR2,-/-,-,-/-,false,false,false,enable,-,always,']
*   ['VDOM1','internal1','wan2','4to4' ,'1234','' ,'1','deny','SRVCG4' ,'ADDR1','SRVCG4' ,'ADDR2','SRVCG4' ,'SRVCG4' ,'SRVCG4' ,'false','false','false','enable','-','always',''] -> ['VDOM1,internal1,wan2,4to4,1234,,1,deny,89,ADDR1,-/-,ADDR2,-/-,-,-/-,false,false,false,enable,-,always,',
*                                                                                                                                                                                    'VDOM1,internal1,wan2,4to4,1234,,1,deny,58,ADDR1,-/-,ADDR2,-/-,-,any/any,false,false,false,enable,-,always,',
*                                                                                                                                                                                    'VDOM1,internal1,wan2,4to4,1234,,1,deny,6,ADDR1,eq/any,ADDR2,eq/443,0/0,-/-,false,false,false,enable,-,always,']
*   [''     ,'internal1','wan2','4to4' ,'1234','' ,'1','deny','SRVC13' ,'ADDR1','SRVC13' ,'ADDR2','SRVC13' ,'SRVC13' ,'-/-'    ,'false','false','false','enable','-','always',''] -> [',internal1,wan2,4to4,1234,,1,deny,6,ADDR1,eq/any,ADDR2,eq/443,192.168.0.1/32,-/-,false,false,false,enable,-,always,']
*   [''     ,'internal1','wan2','4to4m','1234','-','1','deny','ip'     ,'ADDR1','-/-'    ,'ADDR2','-/-'    ,'-'      ,'-/-'    ,'-'    ,'-'    ,'-'    ,'enable','-','-'     ,''] -> [',internal1,wan2,4to4m,1234,-,1,deny,ip,ADDR1,-/-,ADDR2,-/-,-,-/-,-,-,-,enable,-,-,']
*   ['VDOM1','internal1','wan2','4to4' ,'1234','' ,'1','deny','UNKNOWN','ADDR1','UNKNOWN','ADDR2','UNKNOWN','UNKNOWN','UNKNOWN','false','false','false','enable','-','always',''] -> ['VDOM1,internal1,wan2,4to4,1234,,1,deny,UNKNOWN,ADDR1,UNKNOWN,ADDR2,UNKNOWN,UNKNOWN,UNKNOWN,false,false,false,enable,-,always,']
*   []                                                                                                                                                                            -> []
*/
const funcFlattenServiceAndServiceGroupOfNormalizedPolicy = function(arrayToken) {
    const arrayFlatString = [];
    const arrayService = getServiceArray(arrayToken);
    if (arrayService[0]) {
        let index = 0;
        for (let i=0; i<arrayService.length; ++i) {
            const arrayServiceAndDstaddr = arrayService[i].split(';');
            const array = arrayServiceAndDstaddr[0].split('/');
            const strProtocol = array[0];
            let strSrcPort = '-/-';
            let strDstPort = '-/-';
            let strTypeCode = '-/-';
            if (isTcpProtocol(strProtocol) || isUdpProtocol(strProtocol) || isSctpProtocol(strProtocol)) { // TCP, UDP, or SCTP.
                strSrcPort = array[1] + '/' + array[2];
                strDstPort = array[3] + '/' + array[4];
            } else if (isIcmpProtocol(strProtocol) || isIcmp6Protocol(strProtocol)) { // ICMP or ICMP6.
                strTypeCode = array[1] + '/' + array[2];
            } else if (isIpProtocol(strProtocol) || Number.isInteger(+strProtocol)) { // IP.
                // as-is.
            } else { // Unknown protocol.
                strSrcPort = strProtocol;
                strDstPort = strProtocol;
                strTypeCode = strProtocol;
            }

            arrayFlatString[index] = arrayToken[NMCOL_DOM_NAME];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_SRC_INTF];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_DST_INTF];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_POL_TYPE];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_POL_ID];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_POL_NAME];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_POL_LINE];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_ACTION];
            arrayFlatString[index] += ',' + strProtocol;
            arrayFlatString[index] += ',' + arrayToken[NMCOL_SRC_ADDR];
            arrayFlatString[index] += ',' + strSrcPort;
            arrayFlatString[index] += ',' + arrayToken[NMCOL_DST_ADDR];
            arrayFlatString[index] += ',' + strDstPort;
            arrayFlatString[index] += ',' + arrayServiceAndDstaddr[1]; // Service destination address.
            arrayFlatString[index] += ',' + strTypeCode;
            arrayFlatString[index] += ',' + arrayToken[NMCOL_SRCADDR_NEGATE];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_DSTADDR_NEGATE];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_SERVICE_NEGATE];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_STATUS];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_LOG];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_SCHEDULE];
            arrayFlatString[index] += ',' + arrayToken[NMCOL_COMMENT];
            ++index;
        }
    }
    return arrayFlatString;
};

/**
* This function flattens the objects and group objects of normalized policy
* using the specified argument and returns the strings array of all flattened
* policies.
*
* @param {Array} arrayNormalizedPolicy - Array of normalized policies.
* @param {function} funcFlatten - Flatten function.
* @return {Array} Strings array of all flattened policies.
*
* @example
*   Variables state when calls.
*   ----------------------------------------------------------------------------------------------------------
*   g_Domain_Data[''].address4['ADDR1' ] = {value:['192.168.0.1/32'], comment:''}
*   g_Domain_Data[''].address4['ADDR2' ] = {value:['192.168.0.2/32'], comment:''}
*   g_Domain_Data[''].address6['ADDR1' ] = {value:['2001:0db8:0000:0000:0000:0000:0000:0001/128'], comment:''}
*   g_Domain_Data[''].address6['ADDR2' ] = {value:['2001:0db8:0000:0000:0000:0000:0000:0002/128'], comment:''}
*   g_Domain_Data[''].service_custom['SRVC1'] = {value:['1/any/any;-'], comment:''}
*   g_Domain_Data[''].service_custom['SRVC2'] = {value:['6/eq/any/eq/443;0/0'], comment:''}
*
*   arrayNormalizedPolicy                                                                                            funcFlatten                                            Return
*   --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   [',internal1,wan2,4to4,1234,,1,deny,SRVC1,ADDR1,-/-,ADDR2,-/-,-,SRVC1,false,false,false,enable,-,always,',       funcFlattenAddressAndAddressGroupOfNormalizedPolicy -> [',internal1,wan2,4to4,1234,,1,deny,SRVC1,192.168.0.1/32,-/-,192.168.0.2/32,-/-,-,SRVC1,false,false,false,enable,-,always,',
*    ',internal1,wan2,6to6,1234,,1,deny,SRVC2,ADDR1,SRVC2,ADDR2,SRVC2,SRVC2,-/-,false,false,false,enable,-,always,']                                                         ',internal1,wan2,6to6,1234,,1,deny,SRVC2,2001:0db8:0000:0000:0000:0000:0000:0001/128,SRVC2,2001:0db8:0000:0000:0000:0000:0000:0002/128,SRVC2,SRVC2,-/-,false,false,false,enable,-,always,']
*   [',internal1,wan2,4to4,1234,,1,deny,SRVC1,ADDR1,-/-,ADDR2,-/-,-,SRVC1,false,false,false,enable,-,always,',       funcFlattenServiceAndServiceGroupOfNormalizedPolicy -> [',internal1,wan2,4to4,1234,,1,deny,1,ADDR1,-/-,ADDR2,-/-,-,any/any,false,false,false,enable,-,always,',
*    ',internal1,wan2,6to6,1234,,1,deny,SRVC2,ADDR1,SRVC2,ADDR2,SRVC2,SRVC2,-/-,false,false,false,enable,-,always,']                                                         ',internal1,wan2,6to6,1234,,1,deny,6,ADDR1,eq/any,ADDR2,eq/443,0/0,-/-,false,false,false,enable,-,always,']
*/
function flattenObjectAndGroupObjectOfNormalizedPolicy(arrayNormalizedPolicy, funcFlatten) {
    const arrayFlattenedString = [];
    for (let i=0; i<arrayNormalizedPolicy.length; ++i) {
        // Split by a comma.
        const arrayToken = arrayNormalizedPolicy[i].split(',');

        // Flatten the objects and object-groups.
        arrayFlattenedString.push(...funcFlatten(arrayToken));
    }
    return arrayFlattenedString;
}

/**
* This function flattens the objects and group objects of all normalized
* policies and saves them into the specified array. It can specify by
* boolAddress and boolService arguments what kind of object flatten.
*
* @param {boolean} boolAddress - True when flattens the address objects and
*     address-group objects.
* @param {boolean} boolService - True when flattens the service objects and
*     service-group objects.
* @param {Array} arrayAllFlattenedPolicies - Array to save all flattened
*     policies.
*
* @example
*   Variables state when calls.
*   -----------------------------------------------------------------------------------------------------------------------------------------------
*   g_Domain_Data[''].address4['ADDR1' ] = {value:['192.168.0.1/32'], comment:''}
*   g_Domain_Data[''].address4['ADDR2' ] = {value:['192.168.0.2/32'], comment:''}
*   g_Domain_Data[''].address6['ADDR1' ] = {value:['2001:0db8:0000:0000:0000:0000:0000:0001/128'], comment:''}
*   g_Domain_Data[''].address6['ADDR2' ] = {value:['2001:0db8:0000:0000:0000:0000:0000:0002/128'], comment:''}
*   g_Domain_Data[''].service_custom['SRVC1'] = {value:['1/any/any;-'], comment:''}
*   g_Domain_Data[''].service_custom['SRVC2'] = {value:['6/eq/any/eq/443;0/0'], comment:''}
*   g_Domain_Data[''].policy4to4 = [',internal1,wan2,4to4,1234,,1,deny,SRVC1,ADDR1,-/-,ADDR2,-/-,-,SRVC1,false,false,false,enable,-,always,']
*   g_Domain_Data[''].policy6to6 = [',internal1,wan2,6to6,1234,,1,deny,SRVC2,ADDR1,SRVC2,ADDR2,SRVC2,SRVC2,-/-,false,false,false,enable,-,always,']
*   g_Domain_Data['VDOM1'].address4['ADDR1'] = {value:['192.168.1.1/32'], comment:''}
*   g_Domain_Data['VDOM1'].address4['ADDR2'] = {value:['192.168.1.2/32'], comment:''}
*   g_Domain_Data['VDOM1'].address6['ADDR1'] = {value:['2001:0db8:1000:0000:0000:0000:0000:0001/128'], comment:''}
*   g_Domain_Data['VDOM1'].service_custom['SRVC1'] = {value:['58/8/any;-'], comment:''}
*   g_Domain_Data['VDOM1'].policy6to4 = ['VDOM1,internal1,wan2,6to4,1234,-,1,deny,SRVC1,ADDR1,-/-,ADDR2,-/-,-,SRVC1,-,-,-,enable,-,always,']
*   g_Domain_Data['VDOM1'].policy4to4m = ['VDOM1,internal1,wan2,4to4m,1234,-,1,deny,58,ADDR1,-/-,ADDR2,-/-,-,any/any,-,-,-,enable,-,-,']
*
*   boolAddress boolService arrayAllFlattenedPolicies    arrayAllFlattenedPolicies
*   -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
*   false       false       []                        -> [',internal1,wan2,4to4,1234,,1,deny,SRVC1,ADDR1,-/-,ADDR2,-/-,-,SRVC1,false,false,false,enable,-,always,',
*                                                         ',internal1,wan2,6to6,1234,,1,deny,SRVC2,ADDR1,SRVC2,ADDR2,SRVC2,SRVC2,-/-,false,false,false,enable,-,always,',
*                                                         'VDOM1,internal1,wan2,6to4,1234,-,1,deny,SRVC1,ADDR1,-/-,ADDR2,-/-,-,SRVC1,-,-,-,enable,-,always,',
*                                                         'VDOM1,internal1,wan2,4to4m,1234,-,1,deny,58,ADDR1,-/-,ADDR2,-/-,-,any/any,-,-,-,enable,-,-,']
*   true        false       [an existing policy]      -> [',internal1,wan2,4to4,1234,,1,deny,SRVC1,192.168.0.1/32,-/-,192.168.0.2/32,-/-,-,SRVC1,false,false,false,enable,-,always,',
*                                                         ',internal1,wan2,6to6,1234,,1,deny,SRVC2,2001:0db8:0000:0000:0000:0000:0000:0001/128,SRVC2,2001:0db8:0000:0000:0000:0000:0000:0002/128,SRVC2,SRVC2,-/-,false,false,false,enable,-,always,',
*                                                         'VDOM1,internal1,wan2,6to4,1234,-,1,deny,SRVC1,2001:0db8:1000:0000:0000:0000:0000:0001/128,-/-,192.168.1.2/32,-/-,-,SRVC1,-,-,-,enable,-,always,',
*                                                         'VDOM1,internal1,wan2,4to4m,1234,-,1,deny,58,192.168.1.1/32,-/-,224.0.1.1/32,-/-,-,any/any,-,-,-,enable,-,-,']
*   false       true        []                        -> [',internal1,wan2,4to4,1234,,1,deny,1,ADDR1,-/-,ADDR2,-/-,-,any/any,false,false,false,enable,-,always,',
*                                                         ',internal1,wan2,6to6,1234,,1,deny,6,ADDR1,eq/any,ADDR2,eq/443,0/0,-/-,false,false,false,enable,-,always,'
*                                                         'VDOM1,internal1,wan2,6to4,1234,-,1,deny,58,ADDR1,-/-,ADDR2,-/-,-,8/any,-,-,-,enable,-,always,',
*                                                         'VDOM1,internal1,wan2,4to4m,1234,-,1,deny,58,ADDR1,-/-,ADDR2,-/-,-,any/any,-,-,-,enable,-,-,']
*   true        true        []                        -> [',internal1,wan2,4to4,1234,,1,deny,1,192.168.0.1/32,-/-,192.168.0.2/32,-/-,-,any/any,false,false,false,enable,-,always,',
*                                                         ',internal1,wan2,6to6,1234,,1,deny,6,2001:0db8:0000:0000:0000:0000:0000:0001/128,eq/any,2001:0db8:0000:0000:0000:0000:0000:0002/128,eq/443,0/0,-/-,false,false,false,enable,-,always,',
*                                                         'VDOM1,internal1,wan2,6to4,1234,-,1,deny,58,2001:0db8:1000:0000:0000:0000:0000:0001/128,-/-,192.168.1.2/32,-/-,-,8/any,-,-,-,enable,-,always,',
*                                                         'VDOM1,internal1,wan2,4to4m,1234,-,1,deny,58,192.168.1.1/32,-/-,224.0.1.1/32,-/-,-,any/any,-,-,-,enable,-,-,']
*/
function flattenAllNormalizedPolicies(boolAddress, boolService, arrayAllFlattenedPolicies) {
    arrayAllFlattenedPolicies.length = 0;

    const flattenNormalizedPolicies = function(arrayNormalizedPolicies) {
        for (let i=0; i<arrayNormalizedPolicies.length; ++i) {
            let arrayFlattenedPolicy = [];
            arrayFlattenedPolicy[0] = arrayNormalizedPolicies[i];
            if (boolAddress) {
                arrayFlattenedPolicy = flattenObjectAndGroupObjectOfNormalizedPolicy(arrayFlattenedPolicy, funcFlattenAddressAndAddressGroupOfNormalizedPolicy);
            }
            if (boolService) {
                arrayFlattenedPolicy = flattenObjectAndGroupObjectOfNormalizedPolicy(arrayFlattenedPolicy, funcFlattenServiceAndServiceGroupOfNormalizedPolicy);
            }

            // Save the result that all objects and group objects are flattened.
            arrayAllFlattenedPolicies.push(...arrayFlattenedPolicy);
        }
    };

    for (const key in g_Domain_Data) {
        if (g_Domain_Data.hasOwnProperty(key)) {
            for (let i=0; i<t_PolicyPropertyName.length; ++i) {
                if (g_Domain_Data[key][t_PolicyPropertyName[i]]) {
                    flattenNormalizedPolicies(g_Domain_Data[key][t_PolicyPropertyName[i]]);
                }
            }
        }
    }
}

/*
* ============================================================================
* Address lookup functions
* ============================================================================
*/

/**
* This function returns true if the lookup address is within the to be looked
* up address. Otherwise, it is false. If the lookup address is a host address,
* test that address is within. If the lookup address is a network segment,
* test whether all network segment addresses are within. For IPv6, the address
* must be in the full represented format.
*
* @param {string} strAddrToBeLookedUp - Address string to be looked up.
* @param {string} strLookupAddr - Lookup address string.
* @param {number} intLookupAddrType - Lookup address type.
* @param {boolean} boolNegate - True when negates the return value.
* @param {boolean} boolFqdnAndGeoMatchAll -
*   true when FQDN and geography match all other address types.
*   false when FQDN and geography match only the same address type.
* @return {boolean}
*   true if the lookup address is within the to be looked up address.
*   Otherwise, it is false.
*
* @example
*   boolNegate Return  Negated return
*   ---------------------------------
*   false      false   false
*   false      true    true
*   true       false   true
*   true       true    false
*
*/
function isWithin(strAddrToBeLookedUp, strLookupAddr, intLookupAddrType, boolNegate, boolFqdnAndGeoMatchAll) {
    if ((intLookupAddrType == LOOKUP_ADDRESS_TYPE_IPV4 && strAddrToBeLookedUp === '0.0.0.0/0') ||
        (intLookupAddrType == LOOKUP_ADDRESS_TYPE_IPV6 && strAddrToBeLookedUp === '0000:0000:0000:0000:0000:0000:0000:0000/0')) {
        return !boolNegate;
    }

    if (intLookupAddrType == LOOKUP_ADDRESS_TYPE_GEO) { // GEO.
        if  (strAddrToBeLookedUp.startsWith('geo:')) {
            return ((boolNegate ^ (strLookupAddr === strAddrToBeLookedUp.substring(4))) != 0); // Country names are identical.
        }
        // The looked-up address is IPv4, IPv4 range, IPv4 wildcard, IPv6, IPv6 range, FQDN, or Wildcard FQDN.
        return ((boolNegate ^ boolFqdnAndGeoMatchAll) != 0);
    }
    if (intLookupAddrType == LOOKUP_ADDRESS_TYPE_FQDN) { // FQDN.
        if (strAddrToBeLookedUp.startsWith('fqdn:')) { // The looked-up address is FQDN or Wildcard FQDN.
            const wfqdn = new WildcardFQDN;
            wfqdn.name = strAddrToBeLookedUp.substring(5);
            return ((boolNegate ^ wfqdn.test(strLookupAddr)) != 0);
        }
        // The looked-up address is IPv4, IPv4 range, IPv4 wildcard, IPv6, IPv6 range, or geography.
        return ((boolNegate ^ boolFqdnAndGeoMatchAll) != 0);
    }
    if (intLookupAddrType == LOOKUP_ADDRESS_TYPE_IPV4) { // IPv4.
        if (strAddrToBeLookedUp.startsWith('geo:') || strAddrToBeLookedUp.startsWith('fqdn:')) { // The looked-up address is FQDN, Wildcard FQDN, or geography.
            return ((boolNegate ^ boolFqdnAndGeoMatchAll) != 0);
        } else if (strAddrToBeLookedUp.indexOf(':') != -1) { // The looked-up address is IPv6, IPv6 range format.
            // Nothing to do.
        } else if (strAddrToBeLookedUp.indexOf('-') != -1) { // The looked-up address is IPv4 range format.
            if (isIPv4WithPrefixLengthIncludedInRange(strLookupAddr, strAddrToBeLookedUp)) { // IPv4 address is within range.
                return !boolNegate;
            }
        } else {
            const array = strAddrToBeLookedUp.split('/');
            if (array[1]) {
                if (array[1].indexOf('.') == -1) { // The looked-up address is CIDR format.
                    if (isIPv4WithPrefixLengthIncludedInSegment(strLookupAddr, strAddrToBeLookedUp)) { // IPv4 address is within the segment.
                        return !boolNegate;
                    }
                } else { // The looked-up address is wildcard format.
                    if (isIPv4WithPrefixLengthIncludedInFortinetWildcardAddr(strLookupAddr, strAddrToBeLookedUp)) { // IPv4 address matches the wildcard address.
                        return !boolNegate;
                    }
                }
            }
        }
    }
    if (intLookupAddrType == LOOKUP_ADDRESS_TYPE_IPV6) { // IPv6.
        if (strAddrToBeLookedUp.startsWith('geo:') || strAddrToBeLookedUp.startsWith('fqdn:')) { // The looked-up address is FQDN, Wildcard FQDN, or geography.
            return ((boolNegate ^ boolFqdnAndGeoMatchAll) != 0);
        } else if (strAddrToBeLookedUp.indexOf(':') == -1) { // IPv4, IPv4 range, or IPv4 wildcard.
            // Nothing to do.
        } else if (strAddrToBeLookedUp.indexOf('-') != -1) { // The looked-up address is range format.
            if (isIPv6WithPrefixLengthIncludedInRange(strLookupAddr, strAddrToBeLookedUp)) { // IPv6 address is within range.
                return !boolNegate;
            }
        } else if (strAddrToBeLookedUp.indexOf('/') != -1) { // The looked-up address is CIDR format.
            if (isIPv6WithPrefixLengthIncludedInSegment(strLookupAddr, strAddrToBeLookedUp)) { // IPv6 address is within the segment.
                return !boolNegate;
            }
        }
    }
    return boolNegate;
}

/**
* This function looks up the specified source address and destination address
* in normalized policies and saves the matched entries into the specified
* array. All matched entries are saved into arrayResult, and the matched
* entries except ineffectual policies are saved into
* arrayResultWithoutIneffectual. The following prefix is appended to the
* matched entries.
*
*   - 'from_192.168.0.1,' if only the source address looks up.
*   - 'to_2001:db8::1/128,' if only the destination address looks up.
*   - 'from_192.168.0.1_to_2001:db8::1/128,'
*     if both the source address and the destination address look up.
*
* If the lookup address string is empty, this function does not look up its
* address. IPv6 address can contain the compressed format.
*
* @param {Array} arrayNormalizedPolicyToBeLookedUp -
*   Normalized policies array to be looked up.
* @param {string} strSrcAddr - Lookup source address string.
* @param {number} intSrcAddrType - Lookup Source address type.
* @param {string} strDstAddr - Lookup destination address string.
* @param {number} intDstAddrType - Lookup destination address type.
* @param {boolean} boolFqdnAndGeoMatchAll -
*   true when FQDN and geography match all other address types.
*   false when FQDN and geography match only the same address type.
* @param {Array} arrayResult - Array to save all matched entries.
* @param {Array} arrayResultWithoutIneffectual -
*   Array to save all matched entries except ineffectual policies.
*
*/
function lookUpAddrInNormalizedPoliciesArray(arrayNormalizedPolicyToBeLookedUp, strSrcAddr, intSrcAddrType, strDstAddr, intDstAddrType, boolFqdnAndGeoMatchAll, arrayResult, arrayResultWithoutIneffectual) {
    // Stop look up if the lookup address is an invalid IPv6 address.
    let strSrcFullAddr = strSrcAddr;
    if (intSrcAddrType == LOOKUP_ADDRESS_TYPE_IPV6) {
        strSrcFullAddr = getIPv6FullRepresentedAddrWithPrefixLength(strSrcAddr);
        if (strSrcFullAddr === '') {
            return;
        }
    }
    let strDstFullAddr = strDstAddr;
    if (intDstAddrType == LOOKUP_ADDRESS_TYPE_IPV6) {
        strDstFullAddr = getIPv6FullRepresentedAddrWithPrefixLength(strDstAddr);
        if (strDstFullAddr === '') {
            return;
        }
    }

    //
    const objPolicyIneffectual = {};

    for (let i=0; i<arrayNormalizedPolicyToBeLookedUp.length; ++i) {
        const strLine = arrayNormalizedPolicyToBeLookedUp[i];
        const arrayToken = strLine.split(',');

        const isAddrType4to4 = arrayToken[NMCOL_POL_TYPE] === '4to4' || arrayToken[NMCOL_POL_TYPE] === '4to4m';
        const isAddrType6to6 = arrayToken[NMCOL_POL_TYPE] === '6to6' || arrayToken[NMCOL_POL_TYPE] === '6to6m';
        const isAddrType4to6 = arrayToken[NMCOL_POL_TYPE] === '4to6';
        const isAddrType6to4 = arrayToken[NMCOL_POL_TYPE] === '6to4';

        // Skip if the address type is not matched with the lookup address type.
        if ((isAddrType4to4 && (intSrcAddrType == LOOKUP_ADDRESS_TYPE_IPV6 || intDstAddrType == LOOKUP_ADDRESS_TYPE_IPV6)) ||
            (isAddrType4to6 && (intSrcAddrType == LOOKUP_ADDRESS_TYPE_IPV6 || intDstAddrType == LOOKUP_ADDRESS_TYPE_IPV4)) ||
            (isAddrType6to4 && (intSrcAddrType == LOOKUP_ADDRESS_TYPE_IPV4 || intDstAddrType == LOOKUP_ADDRESS_TYPE_IPV6)) ||
            (isAddrType6to6 && (intSrcAddrType == LOOKUP_ADDRESS_TYPE_IPV4 || intDstAddrType == LOOKUP_ADDRESS_TYPE_IPV4))) {
            continue;
        }

        // Get the service destination address.
        const strServiceDstAddr = arrayToken[NMCOL_SERVICE_DSTADDR];

        // Get the negate parameters.
        const isSrcAddrNegate = arrayToken[NMCOL_SRCADDR_NEGATE] === 'enable';
        const isDstAddrNegate = arrayToken[NMCOL_DSTADDR_NEGATE] === 'enable';
        const isServiceNegate = arrayToken[NMCOL_SERVICE_NEGATE] === 'enable';

        // Test whether the lookup address matches the current line.
        let boolSrcMatched = false;
        let boolDstMatched = false;
        let boolBothMatched = false;
        let str1stColumn = '';
        if (intSrcAddrType != LOOKUP_ADDRESS_TYPE_UNKNOWN && intDstAddrType == LOOKUP_ADDRESS_TYPE_UNKNOWN) {
            boolSrcMatched = isWithin(arrayToken[NMCOL_SRC_ADDR], strSrcFullAddr, intSrcAddrType, isSrcAddrNegate, boolFqdnAndGeoMatchAll);
            str1stColumn = 'from_' + (intSrcAddrType == LOOKUP_ADDRESS_TYPE_FQDN ? 'fqdn:' : intSrcAddrType == LOOKUP_ADDRESS_TYPE_GEO ? 'geo:' : '') + strSrcAddr;
        } else if (intSrcAddrType == LOOKUP_ADDRESS_TYPE_UNKNOWN && intDstAddrType != LOOKUP_ADDRESS_TYPE_UNKNOWN) {
            boolDstMatched = isWithin(arrayToken[NMCOL_DST_ADDR], strDstFullAddr, intDstAddrType, isDstAddrNegate, boolFqdnAndGeoMatchAll);
            str1stColumn = 'to_' + (intDstAddrType == LOOKUP_ADDRESS_TYPE_FQDN ? 'fqdn:' : intDstAddrType == LOOKUP_ADDRESS_TYPE_GEO ? 'geo:' : '') + strDstAddr;
            if (strServiceDstAddr !== '0/0' && strServiceDstAddr !== '-') {
                boolDstMatched &= isWithin(strServiceDstAddr, strDstFullAddr, intDstAddrType, isServiceNegate, boolFqdnAndGeoMatchAll);
            }
        } else {
            boolBothMatched = isWithin(arrayToken[NMCOL_SRC_ADDR], strSrcFullAddr, intSrcAddrType, isSrcAddrNegate, boolFqdnAndGeoMatchAll) && isWithin(arrayToken[NMCOL_DST_ADDR], strDstFullAddr, intDstAddrType, isDstAddrNegate, boolFqdnAndGeoMatchAll);
            str1stColumn = 'from_' + (intSrcAddrType == LOOKUP_ADDRESS_TYPE_FQDN ? 'fqdn:' : intSrcAddrType == LOOKUP_ADDRESS_TYPE_GEO ? 'geo:' : '') + strSrcAddr +
                           '_to_' + (intDstAddrType == LOOKUP_ADDRESS_TYPE_FQDN ? 'fqdn:' : intDstAddrType == LOOKUP_ADDRESS_TYPE_GEO ? 'geo:' : '') + strDstAddr;
            if (strServiceDstAddr !== '0/0' && strServiceDstAddr !== '-') {
                boolBothMatched &= isWithin(strServiceDstAddr, strDstFullAddr, intDstAddrType, isServiceNegate, boolFqdnAndGeoMatchAll);
            }
        }

        // Save the matched line into arrays.
        if (boolSrcMatched || boolDstMatched || boolBothMatched) {
            const strAdd = str1stColumn + ',' + strLine;
            arrayResult.push(strAdd);

            const strPolicyKey = arrayToken[NMCOL_POL_TYPE] + '_' + arrayToken[NMCOL_SRC_INTF] + '_' + arrayToken[NMCOL_DST_INTF];

            if (arrayToken[NMCOL_ACTION] === 'deny' && arrayToken[NMCOL_STATUS] === 'enable') {
                if (arrayToken[NMCOL_PROTOCOL] === 'ip') {
                    const isSrcAddrIPv4Any = arrayToken[NMCOL_SRC_ADDR] === '0.0.0.0/0';
                    const isSrcAddrIPv6Any = arrayToken[NMCOL_SRC_ADDR] === '0000:0000:0000:0000:0000:0000:0000:0000/0';
                    const isDstAddrIPv4Any = arrayToken[NMCOL_DST_ADDR] === '0.0.0.0/0';
                    const isDstAddrIPv6Any = arrayToken[NMCOL_DST_ADDR] === '0000:0000:0000:0000:0000:0000:0000:0000/0';

                    if ((isAddrType4to4 && isSrcAddrIPv4Any && isDstAddrIPv4Any) || // IPv4 any to IPv4 any.
                        (isAddrType6to6 && isSrcAddrIPv6Any && isDstAddrIPv6Any) || // IPv6 any to IPv6 any.
                        (isAddrType4to6 && isSrcAddrIPv4Any && isDstAddrIPv6Any) || // IPv4 any to IPv6 any.
                        ((boolSrcMatched || boolBothMatched) &&
                            ((isAddrType4to4 && isDstAddrIPv4Any) || // to IPv4 any.
                            ((isAddrType4to6 || isAddrType6to6) && isDstAddrIPv6Any))) // to IPv6 any.
                        ) {
                          objPolicyIneffectual[strPolicyKey] = 1;
                    }
                }
            }

            //
            if (arrayToken[NMCOL_STATUS] === 'enable' && !objPolicyIneffectual[strPolicyKey]) {
                arrayResultWithoutIneffectual.push(strAdd);
            }
        }
    }
}

/**
* This function looks up all addresses of lookup addresses list in normalized
* policies and saves the matched entries into the specified array. The line
* format of the lookup addresses list is following. The comment field can omit.
*
*   - 'source address,,comment' if only the source address looks up.
*   - ',destination address,comment' if only the destination address looks up.
*   - 'source address,destination address,comment'
*     if both the source address and destination address look up.
*
* See lookUpAddrInNormalizedPoliciesArray function for detail.
*
* @param {Array} arrayNormalizedPolicyToBeLookedUp -
*   Normalized policies array to be looked up.
* @param {string} listOfLookUpAddr - Lookup address list.
* @param {boolean} boolFqdnAndGeoMatchAll -
*   true when FQDN and geography match all other address types.
*   false when FQDN and geography match only the same address type.
* @param {Array} arrayResult - Array to save all matched entries.
* @param {Array} arrayResultWithoutIneffectual -
*   Array to save all matched entries except ineffectual policies.
*
*/
function lookUpAddrList(arrayNormalizedPolicyToBeLookedUp, listOfLookUpAddr, boolFqdnAndGeoMatchAll, arrayResult, arrayResultWithoutIneffectual) {
    const arrayText = listOfLookUpAddr.split(/\r\n|\r|\n/);

    arrayResult.length = 0;
    arrayResultWithoutIneffectual.length = 0;
    for (let i=0; i<arrayText.length; ++i) {
        // Trim a line feed at the tail and trim white spaces at both head and tail.
        const strLine = arrayText[i].trim();

        // Skip if white line.
        if (strLine.length == 0) {
            continue;
        }

        // Skip if comment line.
        const strHeadChar = strLine.substring(0, 1);
        if (strHeadChar === '!' || strHeadChar === '#') {
            continue;
        }

        // Skip if neither IPv4, IPv6, FQDN, nor geography.
        const arrayLookupAddr = strLine.split(',');
        let strSrcAddr = arrayLookupAddr[0].trim();
        let strDstAddr = ((arrayLookupAddr[1]) ? arrayLookupAddr[1].trim() : '');
        let intSrcAddrType = LOOKUP_ADDRESS_TYPE_UNKNOWN;
        let intDstAddrType = LOOKUP_ADDRESS_TYPE_UNKNOWN;
        if (strSrcAddr !== '') {
            if (strSrcAddr.startsWith('geo:')) {
                intSrcAddrType = LOOKUP_ADDRESS_TYPE_GEO;
                strSrcAddr = strSrcAddr.substring(4);
            } else if (strSrcAddr.startsWith('fqdn:')) {
                intSrcAddrType = LOOKUP_ADDRESS_TYPE_FQDN;
                strSrcAddr = strSrcAddr.substring(5);
            } else if (strSrcAddr.match(/^\d+\.\d+\.\d+\.\d+\/\d+$/)) {
                intSrcAddrType = LOOKUP_ADDRESS_TYPE_IPV4;
            } else if (strSrcAddr.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                intSrcAddrType = LOOKUP_ADDRESS_TYPE_IPV4;
                strSrcAddr += '/32';
            } else if (strSrcAddr.indexOf(':') != -1) {
                intSrcAddrType = LOOKUP_ADDRESS_TYPE_IPV6;
            } else if (strSrcAddr.match(/^([\dA-Za-z][\dA-Za-z\-]{1,61}[\dA-Za-z](?:\.|))+$/)) {
                intSrcAddrType = LOOKUP_ADDRESS_TYPE_FQDN;
            }
            if (intSrcAddrType == LOOKUP_ADDRESS_TYPE_UNKNOWN) {
                continue;
            }
        }
        if (strDstAddr !== '') {
            if (strDstAddr.startsWith('geo:')) {
                intDstAddrType = LOOKUP_ADDRESS_TYPE_GEO;
                strDstAddr = strDstAddr.substring(4);
            } else if (strDstAddr.startsWith('fqdn:')) {
                intDstAddrType = LOOKUP_ADDRESS_TYPE_FQDN;
                strDstAddr = strDstAddr.substring(5);
            } else if (strDstAddr.match(/^\d+\.\d+\.\d+\.\d+\/\d+$/)) {
                intDstAddrType = LOOKUP_ADDRESS_TYPE_IPV4;
            } else if (strDstAddr.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                intDstAddrType = LOOKUP_ADDRESS_TYPE_IPV4;
                strDstAddr += '/32';
            } else if (strDstAddr.indexOf(':') != -1) {
                intDstAddrType = LOOKUP_ADDRESS_TYPE_IPV6;
            } else if (strDstAddr.match(/^([\dA-Za-z][\dA-Za-z\-]{1,61}[\dA-Za-z](?:\.|))+$/)) {
                intDstAddrType = LOOKUP_ADDRESS_TYPE_FQDN;
            }
            if (intDstAddrType == LOOKUP_ADDRESS_TYPE_UNKNOWN) {
                continue;
            }
        }

        //
        lookUpAddrInNormalizedPoliciesArray(arrayNormalizedPolicyToBeLookedUp, strSrcAddr, intSrcAddrType, strDstAddr, intDstAddrType, boolFqdnAndGeoMatchAll, arrayResult, arrayResultWithoutIneffectual);
    }
}

/*
* ============================================================================
* Async functions
* ============================================================================
*/

/**
* @param {string} configToFlat
* @return {Object} Promise
*/
function async_parseFortiGateConfig(configToFlat) {
    return new Promise((resolve)=>{
        parseFortiGateConfig(configToFlat);
        resolve('');
    });
}

/**
* @param {boolean} boolAddress
* @param {boolean} boolService
* @param {Array} arrayAllFlattenedPolicies
* @return {Object} Promise
*/
function async_flattenAllNormalizedPolicies(boolAddress, boolService, arrayAllFlattenedPolicies) {
    return new Promise((resolve)=>{
        flattenAllNormalizedPolicies(boolAddress, boolService, arrayAllFlattenedPolicies);
        resolve('');
    });
}

/**
* @param {Array} arrayNormalizedPolicyToBeLookedUp
* @param {string} listOfLookUpAddr
* @param {boolean} boolFqdnAndGeoMatchAll
* @param {Array} arrayResult
* @param {Array} arrayResultWithoutIneffectual
* @return {Object} Promise
*/
function async_lookUpAddrList(arrayNormalizedPolicyToBeLookedUp, listOfLookUpAddr, boolFqdnAndGeoMatchAll, arrayResult, arrayResultWithoutIneffectual) {
    return new Promise((resolve)=>{
        lookUpAddrList(arrayNormalizedPolicyToBeLookedUp, listOfLookUpAddr, boolFqdnAndGeoMatchAll, arrayResult, arrayResultWithoutIneffectual);
        resolve('');
    });
}

/*
* ============================================================================
* Dedicated Worker thread functions
* ============================================================================
*/

const MSG_MAKE_LIST  = 1;
const MSG_MADE_LIST  = 2;
const MSG_NORMALIZE  = 3;
const MSG_NORMALIZED = 4;
const MSG_FLATTEN    = 5;
const MSG_FLATTENED  = 6;
const MSG_LOOKUP     = 7;
const MSG_LOOKEDUP   = 8;

const g_AllFlattenedPolicies = [];

/**
* This function handles requests from the main thread and sends the responses
* to the main thread.
*
* @param {Object} e : MessageEvent object from the main thread.
*/
var onmessage = function(e) { // eslint-disable-line no-var
    if (e.data[0]) {
        switch (e.data[0]) {
        case MSG_MAKE_LIST:
            g_Domain_Data = {};
            async_parseFortiGateConfig(e.data[1]).then(()=>{
                postMessage([
                    MSG_MADE_LIST,
                    getFirewallAddressListAsString(),
                    getFirewallServiceListAsString(),
                ]);
            });
            break;
        case MSG_NORMALIZE:
            const arrayAllPolicies = [];
            for (const key in g_Domain_Data) {
                if (g_Domain_Data.hasOwnProperty(key)) {
                    for (let i=0; i<t_PolicyPropertyName.length; ++i) {
                        const array = g_Domain_Data[key][t_PolicyPropertyName[i]];
                        if (array) {
                            arrayAllPolicies.push(...array);
                        }
                    }
                }
            }
            postMessage([
                MSG_NORMALIZED,
                arrayAllPolicies.join('\r\n'),
            ]);
            break;
        case MSG_FLATTEN:
            {
                g_AllFlattenedPolicies.length = 0;
                async_flattenAllNormalizedPolicies(
                    e.data[1],
                    e.data[2],
                    g_AllFlattenedPolicies).then(()=>{
                        for (const key in g_Domain_Data) {
                            if (g_Domain_Data.hasOwnProperty(key)) {
                                const array = g_Domain_Data[key].flattened_policy;
                                if (array) {
                                    g_AllFlattenedPolicies.push(...array);
                                }
                            }
                        }
                        postMessage([
                            MSG_FLATTENED,
                            g_AllFlattenedPolicies.join('\r\n'),
                    ]);
                });
            }
            break;
        case MSG_LOOKUP:
            {
                const arrayLookupResult = [];
                const arrayLookupResultEI = [];
                async_lookUpAddrList(g_AllFlattenedPolicies, e.data[1], e.data[2], arrayLookupResult, arrayLookupResultEI).then(()=>{
                    postMessage([
                        MSG_LOOKEDUP,
                        arrayLookupResult.join('\r\n'),
                        arrayLookupResultEI.join('\r\n'),
                    ]);
                });
            }
            break;
        }
    } else {
        console.warn(`WORKER: Received an invalid message.`);
    }
};

/*
* ============================================================================
* ============================================================================
*/

/**
* @param {Object} objDomainData
* @param {string} strProperty
* @return {string} Text lines of the specified object data.
*
*/
function getObjectDataAsString(objDomainData, strProperty) {
    const getValueAndCommentAsString = function(strDomainName, strProperty, object) {
        let strOutput = '';
        for (const key in object) {
            if (object.hasOwnProperty(key)) {
                const array = object[key].value;
                for (let i=0; i<array.length; ++i) {
                    strOutput += strDomainName + ',' + strProperty + ',' + key + ',' + array[i] + ',' + object[key].comment + '\r\n';
                }
            }
        }
        return strOutput;
    };

    let strOutput = '';
    for (const key in objDomainData) {
        if (objDomainData.hasOwnProperty(key)) {
            strOutput += getValueAndCommentAsString(key, strProperty, objDomainData[key][strProperty]);
        }
    }
    return strOutput;
}

/**
* @return {string} Text lines of the firewall address lists.
*
*/
function getFirewallAddressListAsString() {
    let strOutput = '';
    strOutput += getObjectDataAsString(g_Domain_Data, 'address4'         );
    strOutput += getObjectDataAsString(g_Domain_Data, 'multicastaddress4');
    strOutput += getObjectDataAsString(g_Domain_Data, 'addrgrp4'         );
    strOutput += getObjectDataAsString(g_Domain_Data, 'address6'         );
    strOutput += getObjectDataAsString(g_Domain_Data, 'multicastaddress6');
    strOutput += getObjectDataAsString(g_Domain_Data, 'addrgrp6'         );
    return strOutput;
}

/**
* @return {string} Text lines of the firewall service lists.
*
*/
function getFirewallServiceListAsString() {
    let strOutput = '';
    strOutput += getObjectDataAsString(g_Domain_Data, 'service_custom');
    strOutput += getObjectDataAsString(g_Domain_Data, 'service_group' );
    return strOutput;
}

// ===========================================================================
// EOF
// ===========================================================================
