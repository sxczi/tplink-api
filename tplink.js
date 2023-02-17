import fetch from 'node-fetch';
import crypto from 'crypto-js';

import * as cheerio from 'cheerio';

export default class TPLink {
  constructor(username, password) {
    this.username = username;
    this.password = password;

    this.sessionID = '';
    this.authToken = `Authorization=Basic ${btoa(`${this.username}:${crypto.MD5(this.password).toString()}`)}`;

    this.users = {};
    this.blacklist = {};
    this.information = {};

    this.defaultHeaders = {
      Host: '192.168.0.1',
      Connection: 'keep-alive',
      'Upgrade-Insecure-Requests': 1,
      'Accept-Encoding': 'gzip, deflate',
      'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8,nl;q=0.7,zh-TW;q=0.6,zh;q=0.5',
      Cookie: this.authToken
    }
  }

  httpRequest(endpoint, ref) {
    return fetch(`http://192.168.0.1/${endpoint}`, {
      method: 'GET',
      headers: {
        ...this.defaultHeaders,
        Referer: ref
      }
    })
  }

  async login() {
    const request = await this.httpRequest('userRpm/LoginRpm.htm?Save=Save', 'http://192.168.0.1/');
    this.sessionID = (await request.text()).split('/').filter(e => !e.includes('<'))[2];
  }

  async logout() {
    await this.httpRequest(`${this.sessionID}/userRpm/LogoutRpm.htm`, `http://192.168.0.1/${this.sessionID}/userRpm/MenuRpm.htm`);
  }

  async getUsers() {
    const request = await this.httpRequest(`${this.sessionID}/userRpm/AssignedIpAddrListRpm.htm`, `http://192.168.0.1/${this.sessionID}/userRpm/MenuRpm.htm`);

    const $ = cheerio.load((await request.text()));

    const users = $('script').text().slice($('script').text().indexOf('DHCPDynList') - 4, $('script').text().indexOf(';') + 1).split('\n');


    for (let user of users) {
      if (user.includes('DHCPDynList') || user.includes(';')) continue;
      user = user.split(',');

      this.users[user[0].replace(/['"]+/g, '')] = {
        mac: user[1].replace(/['"]+/g, '').replace(/ /, ''),
        ip: user[2].replace(/['"]+/g, '').replace(/ /, ''),
        name: user[0].replace(/['"]+/g, '')
      }
    }
  }

  async turnOffBlacklist() {
    await this.httpRequest(`${this.sessionID}/userRpm/WlanMacFilterRpm.htm?Page=1&Disfilter=1&vapIdx=`, `http://192.168.0.1/${this.sessionID}/userRpm/WlanMacFilterRpm.htm`);
  }

  async turnOnBlacklist() {
    await this.httpRequest(`${this.sessionID}/userRpm/WlanMacFilterRpm.htm?Page=1&Enfilter=1&vapIdx=`, `http://192.168.0.1/${this.sessionID}/userRpm/WlanMacFilterRpm.htm`);
  }

  async addToBlacklist(user) {
    await this.httpRequest(`${this.sessionID}/userRpm/WlanMacFilterRpm.htm?Mac=${user.mac}&Desc=${user.name}&Type=1&entryEnabled=1&Changed=0&SelIndex=0&Page=1&vapIdx=1&Save=Save`, `http://192.168.0.1/${this.sessionID}/userRpm/WlanMacFilterRpm.htm?Add=Add&Page=1&vapIdx=`);

  }

  async removeFromBlacklist(user) {
    await this.httpRequest(`${this.sessionID}/userRpm/WlanMacFilterRpm.htm?Del=${user.index}&Page=1&vapIdx=0`, `http://192.168.0.1/${this.sessionID}/userRpm/WlanMacFilterRpm.htm`);
  }

  async showBlacklist() {
    const request = await this.httpRequest(`http://192.168.0.1/${this.sessionID}/userRpm/WlanMacFilterRpm.htm`, `http://192.168.0.1/${this.sessionID}/userRpm/MenuRpm.htm`);

    const $ = cheerio.load((await request.text()));

    const blacklistusers = $('script:nth-child(2)').text().slice($('script:nth-child(2)').text().indexOf('wlanFilterList') - 4, $('script:nth-child(2)').text().indexOf(';') + 1).split('\n');

    let i = 0;

    for (let user of blacklistusers) {
      if (user.includes('wlanFilterList') || user.includes(';')) continue;
      user = user.split(',');

      this.blacklist[user[4].replace(/['"]+/g, '').replace(/ /, '')] = {
        mac: user[0].replace(/['"]+/g, '').replace(/ /, ''),
        index: i,
        name: user[4].replace(/['"]+/g, '').replace(/ /, ''),
      }

      i += 1;
    }
  }

  async getInfo() {
    const request = await this.httpRequest(`${this.sessionID}/userRpm/StatusRpm.htm`, `http://192.168.0.1/${this.sessionID}/userRpm/Index.htm`);

    const $ = cheerio.load((await request.text()));

    const status = $('script:nth-child(1)').text().slice($('script:nth-child(1)').text().indexOf('statusPara'), $('script:nth-child(1)').text().indexOf(';')).split(',');

    this.information['Firmware version'] = status[5].replace('\n', '').replace(/  /, '').replace(/['"]+/g, '');
    this.information['Hardware version'] = status[6].replace('\n', '').replace(/  /, '').replace(/['"]+/g, '');

    const lanStatus = $('script:nth-child(2)').text().slice($('script:nth-child(2)').text().indexOf('lanPara'), $('script:nth-child(2)').text().indexOf(';')).split(',');

    this.information['MAC address'] = lanStatus[0].split('\n')[1].replace(/['"]+/g, '');
    this.information['IP address'] = lanStatus[1].replace(/['"]+/g, '').replace(/  /g, '');
    this.information['Subnet mask'] = lanStatus[2].replace(/['"]+/g, '').replace(/  /g, '');

    const wirelessStatus = $('script:nth-child(3)').text().slice($('script:nth-child(3)').text().indexOf('wlanPara'), $('script:nth-child(3)').text().indexOf(';')).split(',');

    this.information['SSID'] = wirelessStatus[1].replace('\n', '').replace(/['"]+/g, '');

    let wanStatus = $('script:nth-child(5)').text().slice($('script:nth-child(5)').text().indexOf('wanPara'), $('script:nth-child(5)').text().indexOf(';')).split(',');

    const regex = new RegExp("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")

    wanStatus = wanStatus.filter(entry => regex.test(entry.replace(/['"]+/g, '').replace(/ /g, '')));

    this.information['WAN Port IP'] = wanStatus[0].replace(/['"]+/g, '').replace(/ /g, '')
    this.information['WAN subnet mask'] = wanStatus[1].replace(/['"]+/g, '').replace(/ /g, '');
    this.information['WAN default gateway'] = wanStatus[2].replace(/['"]+/g, '').replace(/ /g, '');
    this.information['WAN DNS server'] = {
      primary: wanStatus[3].replace(/['"]+/g, '').replace(/ /g, ''),
      secondary: wanStatus[4].replace(/['"]+/g, '').replace(/ /g, '')
    }
  }

  async releaseConnection() {
    await this.httpRequest(`${this.sessionID}/userRpm/StatusRpm.htm?ReleaseIp=Release&wan=1`, `http://192.168.0.1/${sessionID}/userRpm/StatusRpm.htm`);
  }

  async renewConnection() {
    await this.httpRequest(`${this.sessionID}/userRpm/StatusRpm.htm?RenewIp=Renew&wan=1`, `http://192.168.0.1/${sessionID}/userRpm/StatusRpm.htm`);
  }

  async reboot() {
    await this.httpRequest(`${this.sessionID}/userRpm/SysRebootRpm.htm?Reboot=Reboot`, `http://192.168.0.1/${sessionID}/userRpm/SysRebootRpm.htm`);
  }

  async changePassword(password) {
    await this.httpRequest(`${this.sessionID}/userRpm/WlanSecurityRpm.htm?secType=3&pskSecOpt=3&pskCipher=3&pskSecret=${password}&interval=0&wpaSecOpt=3&wpaCipher=1&radiusIp=&radiusPort=1812&radiusSecret=&intervalWpa=0&wepSecOpt=3&keytype=1&keynum=1&key1=&length1=0&key2=&length2=0&key3=&length3=0&key4=&length4=0&Save=Save`, `http://192.168.0.1/${this.sessionID}/userRpm/WlanSecurityRpm.htm`);
  }

  async changeSSID(ssid) {
    await this.httpRequest(`${this.sessionID}/userRpm/WlanNetworkRpm.htm?ssid1=${ssid}&ssid2=TP-Link_GUEST_62BE&ssid3=TP-Link_62BE_3&ssid4=TP-Link_62BE_4&region=101&band=0&mode=6&chanWidth=2&channel=15&rate=83&ap=1&broadcast=2&brlssid=&brlbssid=&addrType=1&keytype=1&wepindex=1&authtype=1&keytext=&Save=Save`, `http://192.168.0.1/${this.sessionID}/userRpm/WlanNetworkRpm.htm`);
  }

  async changeDNS(add1, add2) {
    await this.httpRequest(`${this.sessionID}/userRpm/LanDhcpServerRpm.htm?dhcpserver=1&ip1=192.168.0.100&ip2=192.168.0.199&Lease=120&gateway=192.168.0.1&domain=&dnsserver=${add1}&dnsserver2=${add2}&Save=Save`, `http://192.168.0.1/${this.sessionID}/userRpm/LanDhcpServerRpm.htm`);
  }

  async changeAdminAccount(user, pass) {
    let passs = encodeURIComponent(btoa(crypto.MD5(pass).toString()));

    await this.httpRequest(`${this.sessionID}/userRpm/ChangeLoginPwdRpm.htm?oldname=${username}&oldpassword=${encodeURIComponent(btoa(crypto.MD5(password).toString()))}&newname=${user}&newpassword=${passs}&newpassword2=${passs}&Save=Save`, `http://192.168.0.1/${sessionID}/userRpm/ChangeLoginPwdRpm.htm`);

    this.username = user;
    this.password = pass;
  }

  async LEDstatus() {
    const request = await this.httpRequest(`${this.sessionID}/userRpm/LedCtrlRpm.htm`, `http://192.168.0.1/${this.sessionID}/userRpm/MenuRpm.htm`);

    const $ = cheerio.load(await request.text());

    const status = $('script:nth-child(1)').text().slice($('script:nth-child(1)').text().indexOf('ledCtrlPara'), $('script:nth-child(1)').text().indexOf(';')).split(',');

    return {
      LEDstat: status[0].split('\n')[1] === '1' ? 'On' : 'Off',
      currentTime: status[1].replace('\n', '').replace(/['"]+/g, '')
    }
  }

  async turnOffLED() {
    await this.httpRequest(`${this.sessionID}/userRpm/LedCtrlRpm.htm?Disfilter=1`, `http://192.168.0.1/${this.sessionID}/userRpm/LedCtrlRpm.htm`);
  }

  async turnOnLED() {
    await this.httpRequest(`${this.sessionID}/userRpm/LedCtrlRpm.htm?Enfilter=11`, `http://192.168.0.1/${this.sessionID}/userRpm/LedCtrlRpm.htm`)
  }
}