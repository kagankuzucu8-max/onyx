const crypto = require('crypto')

const OKX_BASE = 'https://www.okx.com'

function sign(timestamp, method, path, body, secret) {
  const pre = timestamp + method.toUpperCase() + path + (body ? JSON.stringify(body) : '')
  return crypto.createHmac('sha256', secret).update(pre).digest('base64')
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' }
  }

  let payload
  try { payload = JSON.parse(event.body) }
  catch { return { statusCode: 400, body: JSON.stringify({ code: '1', msg: 'Invalid JSON' }) } }

  const { method, path, body, apiKey, secretKey, passphrase, simulated } = payload

  if (!apiKey || !secretKey || !passphrase) {
    return { statusCode: 401, body: JSON.stringify({ code: '1', msg: 'Missing credentials' }) }
  }

  const timestamp = new Date().toISOString()
  const signature = sign(timestamp, method, path, method !== 'GET' ? body : null, secretKey)

  const headers = {
    'OK-ACCESS-KEY':        apiKey,
    'OK-ACCESS-SIGN':       signature,
    'OK-ACCESS-TIMESTAMP':  timestamp,
    'OK-ACCESS-PASSPHRASE': passphrase,
    'Content-Type':         'application/json',
  }
  if (simulated) headers['x-simulated-trading'] = '1'

  try {
    const fetchOptions = {
      method,
      headers,
    }
    if (method !== 'GET' && body) {
      fetchOptions.body = JSON.stringify(body)
    }

    const res  = await fetch(OKX_BASE + path, fetchOptions)
    const data = await res.json()
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify(data),
    }
  } catch (e) {
    return {
      statusCode: 500,
      body: JSON.stringify({ code: '1', msg: e.message }),
    }
  }
}
