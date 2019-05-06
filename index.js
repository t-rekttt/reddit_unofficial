var hmacSHA256 = require('crypto-js/hmac-sha256');
var CryptoJS = require('crypto-js');
let request = require('request-promise');
let btoa = require('btoa');

let UA = 'Reddit/Version 2.26.3/Build 226514/Android 8.0.0';
let client_vendor_id = 'c879e75f-1d24-4a3b-8464-ce2167d7b974';

request = request.defaults({
  // proxy: 'http://localhost:8080',
  strictSSL: false,
  headers: {
    'User-Agent': UA
  }
});

const secret = '8c7abaa5f905f70400c81bf3a1a101e75f7210104b1991f0cd5240aa80c4d99d';

let errorHandling = (res) => {
  if (res && res.json && res.json.errors && res.json.errors.length) {
    let error_str = res.json.errors.map(err => err[1]).join(', ');
    throw new Error(error_str);
  }

  return res;
}

let sign = (data, secret) => {
  let signed = hmacSHA256(data, secret);

  return signed.toString(CryptoJS.enc.hex);
}

let login = (username, password) => {
  let body = `rem=true&passwd=${encodeURIComponent(password)}&user=${encodeURIComponent(username)}&api_type=json`;

  let ts = Date.now()/1000 | 0;
  let signed_result_data = sign(`Epoch:${ts}|User-Agent:${UA}|Client-Vendor-ID:${client_vendor_id}`, secret);
  let signed_body_data = sign(`Epoch:${ts}|Body:${body}`, secret);

  let headers = {
    'User-Agent': UA,
    'Client-Vendor-ID': client_vendor_id,
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-hmac-signed-body': `1:android:2:${ts}:${signed_body_data}`,
    'X-hmac-signed-result': `1:android:2:${ts}:${signed_result_data}`
  };

  return request.post('https://www.reddit.com/api/v1/login', {
    headers,
    body,
    json: true
  })
  .then(res => errorHandling(res));
}

let authorize = (cookie, modhash, client_id = 'ohXpoqrZYub1kg') => {
  let headers = {
    Cookie: 'reddit_session=' + cookie,
    'X-Modhash': modhash
  }

  return request.post('https://ww.reddit.com/api/v1/authorize', {
    headers,
    form: {
      response_type: 'code',
      state: '9eddc5df-7317-4000-bf88-ec6d2f472cb0',
      scope: '*',
      redirect_uri: 'http://localhost:65010/callback',
      client_id,
      duration: 'permanent',
      authorize: 'allow',
    },
    simple: false,
    resolveWithFullResponse: true
  })
  .then(res => errorHandling(res));
}

let getAccessToken = (code, client_id = 'ohXpoqrZYub1kg', client_secret = 'nmlq8LvaC2ygotp8hcCEBW6NVqI') => {
  return request.post('https://www.reddit.com/api/v1/access_token', {
    headers: {
      'Authorization': 'Basic ' + btoa(`${client_id}:${client_secret}`)
    },
    form: {
      code,
      redirect_uri: 'http://localhost:65010/callback',
      device_id: 'a554e548-3fdf-4187-9e98-dbb93eaab38c',
      grant_type: 'authorization_code'
    }
  })
  .then(res => JSON.parse(res))
  .then(res => errorHandling(res));
}

let loginAndGetAccessToken = (username, password) => {
  return login(username, password)
    .then(res => res.json.data)
    .then(({modhash, cookie}) => authorize(cookie, modhash))
    .then(res => res.headers.location)
    .then(location => location.split('code=')[1])
    .then(code => getAccessToken(code));
}

let getMessages = (access_token) => {
  return request('https://oauth.reddit.com/message/messages/.json?limit=100&feature=link_preview&obey_over18=true&sr_detail=true&expand_srs=true&from_detail=true&api_type=json&raw_json=1&always_show_media=1', {
    headers: {
      'Authorization': 'Bearer ' + access_token
    }
  })
  .then(res => errorHandling(res));
}

let sendMessage = (access_token, text, to, subject) => {
  return request.post('https://oauth.reddit.com/api/compose?feature=link_preview&obey_over18=true&sr_detail=true&expand_srs=true&from_detail=true&api_type=json&raw_json=1&always_show_media=1', {
    headers: {
      'Authorization': 'Bearer ' + access_token
    },
    form: {
      text,
      to,
      subject,
      api_type: 'json'
    }
  })
  .then(res => JSON.parse(res))
  .then(res => errorHandling(res));
}

let replyMessage = (access_token, text, thing_id) => {
  return request.post('https://oauth.reddit.com/api/comment?feature=link_preview&obey_over18=true&sr_detail=true&expand_srs=true&from_detail=true&api_type=json&raw_json=1&always_show_media=1', {
    headers: {
      'Authorization': 'Bearer ' + access_token
    },
    form: {
      text,
      thing_id,
      api_type: 'json'
    }
  })
  .then(res => JSON.parse(res))
  .then(res => errorHandling(res));
}

let register = (email, username, password) => {
  let body = `email=${encodeURIComponent(email)}&passwd2=${encodeURIComponent(password)}&rem=true&passwd=${encodeURIComponent(password)}&user=${encodeURIComponent(username)}&api_type=json`;

  let ts = Date.now()/1000 | 0;
  let signed_result_data = sign(`Epoch:${ts}|User-Agent:${UA}|Client-Vendor-ID:${client_vendor_id}`, secret);
  let signed_body_data = sign(`Epoch:${ts}|Body:${body}`, secret);

  let headers = {
    'User-Agent': UA,
    'Client-Vendor-ID': client_vendor_id,
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-hmac-signed-body': `1:android:2:${ts}:${signed_body_data}`,
    'X-hmac-signed-result': `1:android:2:${ts}:${signed_result_data}`
  };

  return request.post('https://www.reddit.com/api/v1/register', {
    headers,
    body,
    json: true
  })
  .then(res => errorHandling(res));
}

module.exports = { loginAndGetAccessToken, getMessages, sendMessage, replyMessage, register }