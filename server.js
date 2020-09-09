const fs = require('fs'),
	process = require('process'),
	fetch = require('node-fetch'),
	express = require('express'),
	app = express(),
	os = require('os'),
	dns = require('dns'),
	path = require('path'),
	mime = require('mime'),
	util = require('util'),
	http = require('http'),
	https = require('https'),
	compression = require('compression'),
	htmlMinify = require('html-minifier'),
	cookieParser = require('cookie-parser'),
	socksProxyAgent = require('socks-proxy-agent'),
	image = {
		jpeg: require('imagemin-mozjpeg'),
		webp: require('imagemin-webp'),
	};

var config = JSON.parse(fs.readFileSync('config.json','utf-8')),
	public_dir = path.join(__dirname, 'public'),
	args = process.argv.splice(2),
	ssl = {key: fs.readFileSync('ssl/default.key','utf8'), cert: fs.readFileSync('ssl/default.crt','utf8')},
	message_page = fs.readFileSync(path.join(__dirname, '/public/error.html') ,'utf8'),
	httpsAgent = new https.Agent({
		rejectUnauthorized: false,
		keepAlive: true,
	}),
	httpAgent = new http.Agent({
		rejectUnauthorized: false,
		keepAlive: true,
	}),
	genMsg = (req,res,code,value)=>{ try{
		var url = req.url,
			method=req.method;
		
		res.contentType('text/html');
		req.msgShown = true
		
		switch(code){
			case 696: // glorified 404
				res.status(404)
				return res.send(message_page.replace('%TITLE%','Bad domain').replace('%REASON%', (value || `Cannot ${method} ${url}`) ));
				break
			case 697:
				res.status(400)
				return res.send(message_page.replace('%TITLE%',value.code).replace('%REASON%', value.message ));
				break
			case 503:
				res.status(code)
				return res.send(message_page.replace('%TITLE%',code).replace('%REASON%', (value || 'Service unavailable') ));
				break
			case 400:
				res.status(code)
				return res.send(message_page.replace('%TITLE%',code).replace('%REASON%', (value || 'Bad request') ));
				break
			case 403:
				res.status(code)
				return res.send(message_page.replace('%TITLE%',code).replace('%REASON%', (value || 'Access forbidden') ));
				break
			case 404:
			default:
				res.status(code);
				return res.send(message_page.replace('%TITLE%',code).replace('%REASON%',`Cannot ${method} ${url}`));
				break
		}
	}catch(err){}},
	skip_headers = [
		/content-encoding/g,
		/content-security-policy/g,
		/x-frame-options/g,
		/x-cache/g,
		/^cf-/g,
		/strict-transport-security/g,
		
	],
	validURL = (url)=>{
		try{ return new URL(url)
		}catch(err){ return null }
	},
	randomIP = ()=>{
		return (Math.floor(Math.random() * 255) + 1)+'.'+(Math.floor(Math.random() * 255))+'.'+(Math.floor(Math.random() * 255))+'.'+(Math.floor(Math.random() * 255))
	},
	addproto = (url)=>{
		if (!/^(?:f|ht)tps?\:\/\//.test(url))url = "https://" + url;
		return url;
	},
	similar = (a,b)=>{
		var equivalency = 0,
			minLength = (a.length > b.length) ? b.length : a.length,    
			maxLength = (a.length < b.length) ? b.length : a.length;
		
		for(var i=0;i<minLength;i++)if(a[i]==b[i])equivalency++;
		
		var weight = equivalency / maxLength;
		
		return weight * 100;
	},
	ready = ()=>{
		if(config.webserver.listenip=='0.0.0.0' || config.webserver.listenip=='127.0.0.1')config.webserver.listenip='localhost';
		var msg = `Listening on ${config.webserver.ssl ? 'https' : 'http'}://${config.webserver.listenip}:${workerData.port}`;
		process.send({ type: 'started', msg: msg });
	},
	btoa = (str,encoding)=>{
		return Buffer.from(str,'utf8').toString(( typeof encoding == 'undefined' ? 'base64' : encoding))
	},
	atob = (str,encoding)=>{
		return Buffer.from(str, ( typeof encoding == 'undefined' ? 'base64' : encoding)).toString('utf8')
	},
	proxify_url = (req_fullURL, pm_url, url, encode = true)=>{
		if(typeof url != 'string')return url; // if the url given isnt a string, we cant modify it
		
		if(url.match(/^(?=moz-|blob:|javascript:|data:|about:)/gi))return url; // data urls
		
		// //www.domain.tld => https://www.domain.tld
		url = url.replace(/^\/{2}/gi, 'https://');
		
		var pmDirectory = pm_url.href.replace(/(.*?\/)[^\/]*?$/gi, '$1'); // https://www.domain.tld/directory/page.html => https://www.domain.tld/directory/
		
		//   /page.html => /https://www.domain.tld/page.html
		
		url = url.replace(/^\/(?!.{3,}:\/\/)\/?/gi, pm_url.origin + '/'); 
		
		/* bruh => /https://www.domain.tld/test
		// notice the lack of a / at the start
		*/
		
		if(!url.match(/.{3,}:\/\//gi))url = pmDirectory + url
		
		/* url sometimes ends up as like https://localhost:7080/DASH_360.mp4 when it should NOT include the origin url inside of the
		// base64 crap done below below so it should work when replacing it with the pm_url's origin
		*/
		
		url = url.replace(new RegExp('^' + req_fullURL.origin.replace(/\//g, '\\/').replace(/\./g, '\\.') , 'gi'), pm_url.origin);
		
		// url should be formed nicely so just like base64ify it
		
		if(encode && url.length <= 1024)url = req_fullURL.origin + '/?pm_url=' + btoa(url)
		else url = req_fullURL.origin + '/' + url
		
		return url
	},
	proxyAgent = (config.proxy.vpn.enabled == true ? new socksProxyAgent('socks5://' + config.proxy.vpn.socks5) : null)
	sessions = workerData = {};

process.on('message',(data)=>{
	switch(data.type){
		case'workerData':
			
			workerData = data
			
			// start up server stuff
			listen = config.webserver.listenip;
			if(config.webserver.ssl == true){
				server = https.createServer(ssl, app).listen(workerData.port, config.webserver.listenip,ready);
			}else{
				server = http.createServer(app).listen(workerData.port, config.webserver.listenip,ready);
			}
			
			// these are all infinity so its reasonable to have a ton of = things
			server.maxConnections = http.globalAgent.maxSockets = https.globalAgent.maxSockets = Infinity
			
			server.timeout = server.keepAliveTimeout = 15000
			
			
			require('./ws.js')(server);
			
			workerData.banned_ua = eval(workerData.banned_ua);
			
			break
		case'update_session':
			sessions = data.sessions;
			break
	}
});

app.use(cookieParser());

app.use(compression({ level: 2 }));

app.use((req, res, next)=>{
	// nice bodyparser alternative that wont cough up errors
	
	req.start = Date.now();
	
	req.chunks = []
	req.body = {};
	
	req.on('data', chunk=>{ req.chunks.push(chunk) });
	
	req.on('end', ()=>{
		req.raw_body = req.chunks.join('');
		req.str_body = req.raw_body.toString('utf16le');
		
		try{
			var result = {};
			
			req.str_body.split('&').forEach((pair)=>{
				pair = pair.split('=');
				req.body[pair[0]] = decodeURIComponent(pair[1] || '');
			});
		}catch(err){
			req.body = {}
		}
		
		return next();
	});
});

app.use((req,res,next)=>{
	/* hacky implementation of session stuff
	// this will add request.session ( a proxy thing acting as an object so it
	// can see whats being added to push to the centeral script )
	*/
	
	var tmp_data = {
			url_proto: req.get('x-forwarded-proto') || req.protocol
		}
	
	req.fullURL = new URL(tmp_data.url_proto + '://' + req.get('host') + req.originalUrl);
	
	tmp_data.sid = req.cookies['pm_connect.sid']
	tmp_data.cookie = { maxAge: 900000, httpOnly: true/*, domain: req.fullURL.host.match(/\..{2,3}(?:\.?.{2,3}).*?$/gim)*/, secure: true, sameSite: 'Lax' }
	
	/* note: remove the domain: blah stuff when testing on an insecure, rather https:// with that yellow lock icon thing on firefox showing up, makes the sid go out of control */
	
	if(typeof tmp_data.sid == 'undefined' || tmp_data.sid.length <= 7){
		while(true){
			tmp_data.sid =  Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
			if(sessions[tmp_data.sid] != null)continue;
			break;
		}
	}
	
	res.cookie('pm_connect.sid', tmp_data.sid, tmp_data.cookie);
	
	if(sessions[tmp_data.sid] == null)sessions[tmp_data.sid] = {}
	
	sessions[tmp_data.sid].__lastAccess = Date.now();
	sessions[tmp_data.sid].sid = tmp_data.sid;
	sessions[tmp_data.sid].cookie = tmp_data.cookie;
	
	req.session = new Proxy(sessions[tmp_data.sid], {
		set: (target, prop, value)=>{
			Reflect.set(target, prop, value);
			process.send({ type: 'store_set', sid: target.sid, session: target });
		}
	});
	
	delete tmp_data
	return next();
});

app.get('/stats', (req, res, next)=>{
	res.status(200);
	res.contentType('application/json');
	res.send(JSON.stringify({ uptime: process.uptime().toString() }))
});

app.get('/suggestions',(req,res)=>{ // autocomplete urls
	if(typeof req.query.input != 'string' || req.query.input == '')return genMsg(req, res, 400, 'Invalid domain input');
	var suggestions=[], index=0, tldCheck, sorted_list = {}, matched = req.query.input.match(/\..{2,3}(?:\.?.{2,3})?/gim);
	
	res.status(200);
	res.contentType('application/json');
	
	if(matched == null || matched[0] == null)return res.send(JSON.stringify(['com','net','org','io','dev']))
	else tldCheck = matched[0].substr(1);
	
	workerData.tldList.forEach((e,i)=> sorted_list[similar(tldCheck,e)] = e);
	
	Object.entries(sorted_list).sort(((a,b)=>{ return a[0] - b[0] })).reverse().forEach((e,i)=>{
		if(index > 5)return;
		index++;
		suggestions.push(e[1]);
	});
	
	return res.send(JSON.stringify(suggestions));
});

app.get('/prox', (req, res, next)=>{
	if(req.query.url == null)return genMsg(400, req, res, 'Specify a url in your query');
	var url = validURL(addproto(req.query.url));
	
	if(url == null)return genMsg(400, req, res, 'Specify a valid url in your query');
	
	return res.redirect(302, '/' + url.href);
});

app.post('/prox', (req, res, next)=>{
	if(req.body.url == null)return genMsg(400, req, res, 'Specify a url in your body');
	var url = validURL(addproto(req.body.url));
	
	if(url == null)return genMsg(400, req, res, 'Specify a valid url in your body');
	
	return res.redirect(302, '/' + url.href);
});

app.post('/session-url', (req,res,next)=>{
	// check for no url at all or a bad url
	if(req.body.url == null || (typeof req.body.url == 'string' && req.body.url.length == undefined))return genMsg(req, res, 400, 'Specify a url in your post body');
	
	req.session.pm_session = true
	req.session.pm_session_url = req.body.url
	
	res.redirect(302, '/ses/');
});

app.use(async (req,res,next)=>{
	if(req.query.ws != undefined)return next(); // noo websocket script did not handle 
	
	if(req.query.pm_url == null && fs.existsSync(path.join(public_dir, req.fullURL.pathname)) )return next()
	else if(req.fullURL.pathname == '/clear-session'){
		Object.entries(req.session).forEach(e=>{ // clear all session data
			req.session[e[0]] = null
		});
		return res.send(message_page.replace('%TITLE%','Session data cleared').replace('%REASON%', 'All was done with success' ));
	}else if(req.fullURL.pathname.match(/^\/{3}/gi)){ //, //domain.tld => https://domain.tld
		return res.redirect(302, req.fullURL.pathname.replace(/^\/{3}/gi, '/https://'))
	}else if(config.proxy.ban_bots && workerData.banned_ua.test(req.get('user-agent'))){ // request is most likely from a bot
		return genMsg(req, res, 403, 'bad bot!');
	}
	
	var data = {
			contentType: 'text/plain',
			sendData: null,
			response: null,
			fetch_headers: {
				'cookie': (()=>{
					var tmp = ''
					Object.entries(req.cookies).forEach((e,i)=>{
						tmp+= e[0] + '=' + e[1] + ';'
					});
					return tmp
				})(),
			},
			fetch_options: {
				method: req.method,
				redirect: 'follow',
				agent: (_parsedURL)=>{
					if(config.proxy.vpn.enabled){
						return proxyAgent
					}else if(_parsedURL.protocol == 'http:'){
						return httpAgent
					}else{
						return httpsAgent
					}
				},
			},
			return_headers: {},
			clearVariables: ()=>{
				Object.entries(data).forEach(e=>{
					delete data[ e[0] ]
				});
				setTimeout(()=>{
					res = null
					req = null
				}, 200);
			},
		},
		url;
	
	/* ignore if the url is /https:/domain.tld
	// and not /https://domain.tld
	*/
	
	req.url = req.url.replace(/^(\/?)http(s?):\/(?!\/)/gi, '$1http$2://');
	
	var tooManyOrigins = new RegExp(`(?:${req.fullURL.origin.replace(/\//g,'\\/').replace(/\./gi,'\\.')}\/|\/\/${req.fullURL.host.replace(/\\./g,'\\.')})`,'gi');
	
	if(req.url.substr(1).match(tooManyOrigins)){
		res.redirect(307, req.url.replace(tooManyOrigins,''));
		return data.clearVariables();
	}
	
	if(req.query.pm_url != null && validURL(atob(req.query.pm_url)) ){
		url = new URL(atob(req.query.pm_url))
	}else if(req.fullURL.pathname.startsWith('/ses/') ){
		
		if(req.session.pm_session != true)return genMsg(req, res, 403, 'You need a url session to access this page.');
			
		try{
			var tmp = new URL(req.session.pm_session_url);
			url = new URL(tmp.origin + '/' + req.fullURL.pathname.replace(/^\/ses\//gi, '') );
		}catch(err){
			// this was a value set by the client so its a client error
			return genMsg(req,res,400,err.message);
		}
		
	}else try{
		url = new URL(req.fullURL.href.substr(req.fullURL.origin.length + 1));
	}catch(err){
		
		// req.session.ref is only set when the content-type is text/html and is not an iframe or object
		if(req.session.ref != undefined && req.session.ref.length>=1){
			var ref=new URL(req.session.ref),newURL='/'+ref.origin+req.url;
			
			if(newURL == undefined)return genMsg(req,res,404); // not poggers!
			
			return res.redirect(307, newURL); //	/cdn/ => https://domain.tld + /cdn/bruh.js
		}else{
			return genMsg(req,res,404);
		}
	}
	
	// if all went good, url should be an instance of URL
	
	// not a special url modifying mode
	if(!req.session.pm_session){
		// url is off a bit
		if(req.url.substr(1 + url.origin.length) != url.href.substr(url.origin.length)){
			return res.redirect(302, req.fullURL.origin + '/' + url.href) && data.clearVariables();
		}
	}
	
	if(url.href == 'https://discordapp.com/api/v8/auth/login')return res.status(400).contentType('application/json; charset=utf-8').send(JSON.stringify({ email: 'Use the QR code scanner or token login option to access discord' }));
	
	
	if(url.hostname == 'discord.com' && (url.pathname == '/new' || url.pathname == '/'))return res.redirect(307, req.fullURL.origin + '/' + url.origin + '/login') && data.clearVariables();
	
	if(!url.hostname.match(workerData.tldRegex))return genMsg(req,res,696);
	
	/* make a dns lookup to the url hostname, if it resolves to a private ip address such as 192.168.0.1 then
	** we can prevent the request
	** additionally, this can handle invalid urls too giving an getaddrinfo ENOTFOUND error
	** instead of node-fetch giving an error
	*/
	
	if(url.host != '')await dns.lookup(url.host, (err, address, family) => {
		if(err){
			return genMsg(req, res, 400, err.message) && data.clearVariables();
		}else if(!config.proxy.private_ips && address.match(/^(?:192.168.|172.16.|10.0.|127.0)/gi)){
			return genMsg(req, res, 403, 'please dont try to connect to private ips :(') && data.clearVariables();
		}
	});
	
	// pass the req.body as a string as most server sided scripts will parse
	if(req.method.match(/post|patch/gi))data.fetch_options['body'] = req.raw_body;
	
	// handle request headers
	Object.entries(req.headers).forEach((e,i,a)=>{
		var name=e[0].toLowerCase();
		var value=e[1];
		
		// do not include cdn- or cloudflare- headers
		
		if(value.includes(url.host) || name.startsWith('Content-security-policy') || name.startsWith('x-') || name.startsWith('host') || name.startsWith('cf-') || name.startsWith('cdn-loop') ){
		
		}else{ // add the header to the array
			data.fetch_headers[name] = value;
		}
	});
	
	data.fetch_headers['referrer'] = data.fetch_headers['referer'] = url.href
	
	data.fetch_options['headers'] = data.fetch_headers;
	
	data.response = await fetch(url, data.fetch_options).catch(err => {
		data.response == null
		switch(err.code){
			case'HPE_HEADER_OVERFLOW':
				Object.entries(req.cookies).forEach((e,i)=>{ // clear all cookies
					res.clearCookie(e[0]);
				});
				
				return res.redirect(req.url);
				
				break
			default:
				return genMsg(req, res, 400, err);
				
				break
		}
	});
	
	if(req.msgShown || data.response == null)return;
	
	data.sendData = await data.response.buffer();
	
	if(req.session.pm_session != true && data.response != undefined && data.response.redirected == true){ // redirect has happened at least once
		return res.redirect(307, '/' + data.response.url);
	}else if(req.session.pm_session == true && data.response.redirected == true){
		var tmp = new URL(data.response.url),
			tmp2 = '/ses';
		
		// need to set a new url in the session of the origin has changed from a redirect
		
		if(tmp.origin != req.session.pm_session_url){
			req.session.pm_session_url = tmp.origin
		}
		
		tmp2 = '/ses/' + tmp.href.substr(tmp.origin.length + 1); // turn /https://discord.com/ae into /ae as the origin has changed
		
		return res.redirect(307, tmp2);
	}
	
	data.response.headers.forEach((e,i)=>{
		data.return_headers[i] = e
		// if(i == 'content-type')data.contentType = e; //safely set content-type
	});
	
	Object.entries(data.return_headers).forEach((e,i)=>{
		if(skip_headers.some(s_name => e[0].toLowerCase().trim().match(s_name) ))return; // skip header if on list
		
		res.set(e[0], e[1]);
		
		if(e[0].toLowerCase().trim() == 'content-type')data.contentType = e[1]
	});
	
	if(data.response.status.toString().startsWith('20') && data.contentType.startsWith('text/html'))req.session.ref = url.href;
	
	res.status(data.response.status);
	
	if(req.fullURL.href.match(/\.wasm$/gi))data.contentType = 'application/wasm'
	
	// check if mime.getType will return something with font/ to avoid proxying fonts
	
	if(data.contentType.startsWith('application/x-shockwave-flash') || (mime.getType(url.href) != null && mime.getType(url.href).match(/^(?:font|audio|video)\//gi))){
		return res.set('Cache-Control','max-age=31536000') && res.send(data.sendData);
	}
	
	if(data.contentType.startsWith('image')){
		res.set('Cache-Control','max-age=31536000');
		
		switch(data.contentType.match(/^[^\s\/]*?\/([^\s\/;]*)/gi)[0]){
			// case'image/webp': break // cannot double-compress without losing alpha
			case'image/jpeg':
			case'image/jpg':
				try{
					data.sendData = await image.jpeg({ quality: 7 })(data.sendData);
				}catch(err){}
				
				break
			case'image/png':
				try{
					data.sendData = await image.webp({ quality: 25, alphaQuality: 75 })(data.sendData);
				}catch(err){}
				
				break
		}
	}
	
	if(!data.contentType.startsWith('text/') && !data.contentType.startsWith('application/')){
		return res.send(data.sendData) && data.clearVariables();
	}else if(data.contentType.startsWith('text/') || data.contentType.startsWith('application/')){
		data.sendData = (()=>{ var output = ''; data.sendData.toString('utf8').split('\n').forEach(e=> output += e + '\n'); return output })(); // convert buffer to string
		
		var regUrlOri=req.fullURL.origin.replace('.','\\.').replace('/','\\/'), // safe way to have url origin in regex
			urlOri=url.origin.replace('.','\\.').replace('/','\\/'), // safe way to have url origin in regex
			urlDirectory = url.href.replace(/(.*?\/)[^\/]*?$/gi, '$1'); // https://google.com/bruh/ok.html => https://google.com/bruh/
		
		try{
			if(data.contentType.startsWith('text/css'))data.sendData = 
			htmlMinify.minify('<style>' + data.sendData + '</style>', {minifyCSS: true, }).replace(/(?:^<style>|<\/style>$)/gi,'') // cool trick to get htmlMinify to minify a css file and have it display correctly
			.replace(/((?::\s*|\s)url\()("|')?(?=[^\+])([\s\S]*?)\2(\))/gi, (match, p1, p2, p3, p4, offset, string)=>{
				var part = p1,
					quote = (p2 == undefined ? '' : p2),
					toproxy_url = p3,
					end_part = p4;
				
				toproxy_url = proxify_url(req.fullURL, url, toproxy_url, true)
				
				return part + quote + toproxy_url + quote + end_part
			});
		}catch(err){}
		
		if(url.hostname != 'www.youtube.com')data.sendData = data.sendData // run this on not youtube links
		.replace(new RegExp(workerData.ip, 'gi'), randomIP())
		.replace(new RegExp(btoa(workerData.ip), 'gi'), randomIP())
		;
		
		if(data.contentType.startsWith('text/html')){
			data.preload_script_data = {
				pm_url: url.href,
				pm_session: req.session.pm_session,
				pm_session_url: req.session.pm_session_url,
				urlrewrite_date: fs.statSync('./public/pm-cgi/js/urlrewrite.js').mtimeMs,
				inject_date: fs.statSync('./public/pm-cgi/js/inject.js').mtimeMs,
			}
			
			data.sendData = data.sendData
			// replace "//www.domain.com" => "https://www.domain.com"
			.replace(/(\s[\D\S]*?\s*?=\s*?(\"|\'))\/{2}([\s\S]*?)\2/gi, '$1https://$3$2')
			
			// strange attribute names
			.replace(/(xlink:)(href)/gi, '$2')
			
			// /websitelocalfilething => https://domain.tld/websitelocalfilething 
			.replace(/(\s{1,})((?:target|href|data-href|data-src|src|srcset|data|action)\s*?=\s*?(?:"|'))((?!data:|javascript:)\/[\s\S]*?)((?:"|'))/gi,'$1$2' + url.origin + '$3$4')
			
			// ./img/bruh => https://domain.tld/directory/img/bruh
			.replace(/(\s{1,})((?:target|href|data-href|data-src|src|srcset|data|action)\s*?=\s*?(?:"|'))\.\/([\s\S]*?)((?:"|'))/gi,'$1$2' + urlDirectory + '$3$4')
			
			// this does all the proxying magic, "https://www.domain.tld => "https://localhost/https://www.domain.tld
			.replace(/(?<!(?:xmlns|xmlns:web)\s*?=)("|\')(?=https?:\/\/)(.*?)\1/gi, (match, p1, p2, p3, offset, string)=>{
				var quote = p1,
					toproxy_url = p2,
					output = quote + toproxy_url + quote;
				
				if(toproxy_url.startsWith(req.fullURL.origin))return output; // dont reproxy urls
				
				toproxy_url = proxify_url(req.fullURL, url, toproxy_url, false);
				
				output = quote + toproxy_url + quote;
				
				return output
			})
			.replace(/ (integrity|nonce)[\s]*?=[\s]*?".*?" ?/gi,'') // integrity and nonce cant be used 
			.replace(/(?:document|window|location|window.location|document.location)(\.(?:href|host|hostname|pathname|port|protocol|hash|search))/gi,'pm_url$1')
			
			// replace title with Right-To-Left Override
			.replace(/<title.*?>.*?<\/ ?title>/gi,'<title>\u202E</title>')
			
			// replace favicon with default one
			.replace(/("|').[^"']*\.ico(?:\?.*?)?("|')/gi,'$1/favicon.ico$2')
			
			// prevent popups, newtabs, or redirecting iframes
			.replace(/("|')_(?:blank|top|parent)\1/gi,'$1_self$1')
			
			// inject code
			.replace(/(<script(?:.*?)>(?:(?!<\/script>)[\s\S])*<\/script>|<\/head>)/i, '<script data="' + encodeURI(btoa(JSON.stringify( data.preload_script_data, null ))) + '" src="/pm-cgi/js/preload.js?' + fs.statSync('./public/pm-cgi/js/preload.js').mtimeMs + '"></script>$1')
			;
			
			if(req.session.pm_session){
				// replace like the session url is equal to https://discord.com/ and replace all links to the session url with the /ses/
				data.sendData = data.sendData.replace(new RegExp(`("|')${ req.fullURL.origin }\\/${ req.session.pm_session_url }(.*?)\\1`,'gi'),'$1/ses/$2$1');
			}
			
			if(typeof req.query.debug == 'string' && req.query.debug == 'true')data.sendData=data.sendData.replace(/<\/body>/gi,`
			<!-- [POWERMOUSE STATS]
			Worker PID: ${process.pid}
			Port: ${workerData.port}
			Host: ${os.hostname()}
			--></body>`.replace(/\t/g, '')); // allow us to have this formatting with indents but hide in result
			
			switch(url.host){
				case'discord.com':
					data.sendData = data.sendData // hacky discord support
					// API for discord.com is strange but discordapp.com works 
					.replace(`API_ENDPOINT: '//discord.com/api'`,`API_ENDPOINT: '/https://discordapp.com/api'`)
					.replace(/<\/body>/gi,`<script type='text/javascript' src='/pm-cgi/js/discord.js'></script>`)
					;
					break;
				default:break;
			}
			
			// ATTEMPT to minify html content, if this fails then it is not needed
			try{ data.sendData = htmlMinify.minify(data.sendData, {minifyCSS: true, minifyJS: true});
			}catch(err){}
		}
		
		return res.send(data.sendData) && data.clearVariables();
	}
});

app.use('/', express.static(public_dir));