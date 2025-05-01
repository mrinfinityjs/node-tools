// Express example:
//    if (canDo('single-ip',ip, 3, 10)) {
//        console.log('Regular action allowed');
//        allowed = true;
//    } else {
//        res.send('Try again later.');
//        return;
//      }

// canDo(ip, howmany, inhowmnayseconds);
// canDo(ip, howmany, inhowmnayseconds);

// If  'item'  is allowed to do an action, proceed, if not, return false. When checked again if the time limit is up, will allow the action to proceed.

const rateData = new Map();

function canDo(name, id, limit, timeWindowSeconds) {
  const now = Date.now();
  const timeWindow = timeWindowSeconds * 1000;
  const key = `${name}:${id}`;
  
  cleanupOldEntries();
    if (!rateData.has(key)) {
    rateData.set(key, {
      timestamps: [now],
      expiresAt: now + timeWindow
    });
    return true;
  }
  
  const data = rateData.get(key);
  const timestamps = data.timestamps;
  
  const validTimestamps = timestamps.filter(timestamp => 
    now - timestamp < timeWindow
  );
  
  data.timestamps = validTimestamps;
  data.expiresAt = now + timeWindow;
  
  if (validTimestamps.length < limit) {
    data.timestamps.push(now);
    return true;
  }
  
  return false;
}

function cleanupOldEntries() {
  const now = Date.now();
  
  for (const [key, data] of rateData.entries()) {
    if (now > data.expiresAt) {
      rateData.delete(key);
    }
  }
}
