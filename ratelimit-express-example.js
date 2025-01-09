// rate limit example for nodejs webapps - express
                                                 
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const path = require('path');
const ratelimit = {};
const badip_hitcount = {};
const rate_howmany = 5;
const rate_timeframe = 15000; //(* 1000 for ms)

// Can be used later
const rate_glob_howmany = 50;
const five_mins = 300 * 1000;
const rate_glob_timeframe = five_mins;
  
app.set('trust proxy', true);

// Send index.html
// Block if rate limit meets 5 hits within 15 seconds (rate_timeframe)

app.get('/', (req, res) => {
  const ip = (req.ip || req.connection.remoteAddress).split(':')[0];
  if (!ratelimit[ip]) {
    ratelimit[ip] = { count: 0, };
    setTimeout(() => {
      delete ratelimit[ip];
    }, rate_timeframe);
  }
  if (ratelimit[ip]) { ratelimit[ip].count += 1; }
  if (ratelimit[ip].count === rate_howmany) {
    badip_hitcount[ip].count += 1;
  }
  if (ratelimit[ip].count > rate_howmany) {
    console.log(`blocked: ${ip}`);
    return res.status(429).send('Try again later.');
  } 
  res.sendFile(path.join(__dirname, 'index.html'));
});
