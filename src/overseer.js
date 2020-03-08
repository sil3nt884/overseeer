const express = require('express');
const app = express();
const https = require('https');
const fs = require('fs');
const CIDR = require('cidr-js');
const cidr = new CIDR();
const reqeust = require('request');

const log = (...args) => console.log(`[OVERSEER] ${args}`)

const checkIpBlakcList = (ip) => {
  const ips = fs.readFileSync('blacklist.txt', 'utf8').split('\n');
  const ipsAddress = ips.map(ip => {
    if (!ip.includes('/')) {
      return ip;
    }
    return cidr.list(ip);
  });
  const merged = []
    .concat
    .apply([], ipsAddress)
    .map(ip => {
     if(ip.includes('::')) {
       return ip
     }
     return `::${ip}`
  });
  return merged
    .filter(e => e.includes(ip))
    .length > 0;
};

const getPage = (url) => {

  return reqeust(`http://localhost:3000${url}`);
};

app.get('/*', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress
  const badPerson = checkIpBlakcList(ip);
  const url = req.originalUrl;
  if (!badPerson) {
    log('IP ', ip, 'request', url, 'allowed')
    req.pipe(getPage(url)).pipe(res)
      .on('end', () => res.end())
      .on('error', (err) => console.log(err))
  }
  else {
    log('IP ', ip, 'request', url, 'blocked')
    req.socket.end()
    return
  }
});

app.post('/*', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress
  const badPerson = checkIpBlakcList(ip);
  const url = req.originalUrl;
  if (!badPerson) {
    log('IP ', ip, 'request', url, 'allowed')
    req.pipe(getPage(url)).pipe(res)
      .on('end', () => res.end())
      .on('error', (err) => console.log(err))
  }
  else {
    log('IP ', ip, 'request', url, 'blocked')
    req.socket.end()
    return
  }
});


https.createServer({
  key: fs.readFileSync('/etc/letsencrypt/live/points884.com/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/points884.com/fullchain.pem'),
}, app).listen(443);


