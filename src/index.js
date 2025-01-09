import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import { KJUR } from 'jsrsasign'
import { inNumberArray, isBetween, isRequiredAllOrNone, validateRequest } from './validations.js'

dotenv.config()
const app = express()
const port = process.env.PORT || 4000

app.use(express.json(), cors())
app.options('*', cors())

const propValidations = {
  role: inNumberArray([0, 1]),
  expirationSeconds: isBetween(1800, 172800)
}

const schemaValidations = [isRequiredAllOrNone(['meetingNumber', 'role'])]

const coerceRequestBody = (body) => ({
  ...body,
  ...['role', 'expirationSeconds'].reduce(
    (acc, cur) => ({ ...acc, [cur]: typeof body[cur] === 'string' ? parseInt(body[cur]) : body[cur] }),
    {}
  )
})

app.post('/', (req, res) => {
  const requestBody = coerceRequestBody(req.body)
  const validationErrors = validateRequest(requestBody, propValidations, schemaValidations)

  if (validationErrors.length > 0) {
    return res.status(400).json({ errors: validationErrors })
  }

  const { meetingNumber, role, expirationSeconds } = requestBody
  const iat = Math.floor(Date.now() / 1000)
  const exp = expirationSeconds ? iat + expirationSeconds : iat + 60 * 60 * 2
  const oHeader = { alg: 'HS256', typ: 'JWT' }

  const oPayload = {
    appKey: process.env.ZOOM_MEETING_HOST_KEY,
    sdkKey: process.env.ZOOM_MEETING_HOST_KEY,
    mn: meetingNumber,
    role,
    iat,
    exp,
    tokenExp: exp
  }

  const sHeader = JSON.stringify(oHeader)
  const sPayload = JSON.stringify(oPayload)
  const sdkJWT = KJUR.jws.JWS.sign('HS256', sHeader, sPayload, process.env.ZOOM_MEETING_HOST_SECRET)
  return res.json({ signature: sdkJWT })
})

app.get('/get-access-token', async (req, res) => {
  try {
    const body = new URLSearchParams({
      grant_type: 'account_credentials',
      account_id: process.env.ZOOM_MEETING_ACCOUNT_ID,
      client_id: process.env.ZOOM_MEETING_HOST_KEY,
      client_secret: process.env.ZOOM_MEETING_HOST_SECRET
    }).toString()
    const response = await fetch('https://zoom.us/oauth/token', {
      method: 'POST',
      body: body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })

    if (!response.ok) {
      return res.status(response.status).json({ error: 'Failed to fetch access token', details: await response.text() })
    }

    const data = await response.json()
    res.json(data) // Return the access token and other response details
  } catch (error) {
    console.error('Error fetching access token:', error)
    res.status(500).json({ error: 'Internal Server Error' })
  }
})

app.post('/zakToken', async (req, res) => {
  try {
    const response = await fetch('https://api.zoom.us/v2/users/me/token?type=zak', {
      method: 'GET',
      headers: {
        'Content-type': 'application/json',
        Authorization: `Bearer ${req.body.accesstoken}`
      }
    })

    if (!response.ok) {
      return res.status(response.status).json({ error: 'Failed to fetch Zak token', details: await response.text() })
    }

    const data = await response.json()
    res.json(data) // Return the access token and other response details
  } catch (error) {
    console.error('Error fetching access token:', error)
    res.status(500).json({ error: 'Internal Server Error' })
  }
})

app.listen(port, () => console.log(`Zoom Meeting SDK Auth Endpoint Sample Node.js, listening on port ${port}!`))
