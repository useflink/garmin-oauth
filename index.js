const fetch=require('node-fetch');
const OAuth = require('oauth-1.0a');
const crypto=require('crypto');
const querystring = require('querystring');
const hash_function_sha1 = (base_string, key) => crypto.createHmac('sha1', key).update(base_string).digest('base64');
const consumer = { key: process.env.CONSUMER_KEY, secret: process.env.CONSUMER_SECRET };
const oauth = OAuth({consumer: consumer, signature_method: 'HMAC-SHA1',hash_function: hash_function_sha1});
let headers, request, status;

const garminAuth = {
	credentials : {},
	requestTokenUrl: "https://connectapi.garmin.com/oauth-service/oauth/request_token",
  authorizeUrl:    "https://connect.garmin.com/oauthConfirm",
  accessTokenUrl:  "https://connectapi.garmin.com/oauth-service/oauth/access_token",
	userIdEndpoint: 	"https://apis.garmin.com/wellness-api/rest/user/id",
	requestToken : async () => {
		request = {
			url: garminAuth.requestTokenUrl,
			method: 'POST',
		};
		headers = oauth.toHeader(oauth.authorize(request))
		let result = await fetch(request.url,{method: request.method, headers: headers,}).then(r=>{status=r.status;return r.text();});
		if (status === 200){
			garminAuth.credentials = querystring.parse(result);
			return result;
		}
		else
			return null;
	},
	getAuthUrl : async () => await garminAuth.requestToken().then(t=>garminAuth.authorizeUrl+'?'+t),
	accessToken : async (verifier) => {
		request = {
			url: garminAuth.accessTokenUrl,
			method: 'POST',
			data: {oauth_verifier:verifier}
		};
		headers = oauth.toHeader(oauth.authorize(request,{key:garminAuth.credentials.oauth_token,secret:garminAuth.credentials.oauth_token_secret}))
		let result = await fetch(request.url,{method: request.method, headers: headers,}).then(r=>{status=r.status;return r.text();});
		if (status === 200){
			garminAuth.credentials = querystring.parse(result);
			return result;
		}
		else
			return null;
	},
	getUserId : async () => {
		return garminAuth.makeSignedRequest(garminAuth.userIdEndpoint);
	},
	makeSignedRequest : async (url, method='GET') => {
		if (!garminAuth.credentials.oauth_token || !garminAuth.credentials.oauth_token_secret)
			return null;
		request = {
			url: url,
			method: method,
		};
		headers = oauth.toHeader(oauth.authorize(request,{key:garminAuth.credentials.oauth_token,secret:garminAuth.credentials.oauth_token_secret}))
		let result = await fetch(request.url,{method: request.method, headers: headers,}).then(r=>{status=r.status;return r.json();});
		if (status === 200){
			return result;
		}
		else
			return null;
	}

}

module.exports=garminAuth;
