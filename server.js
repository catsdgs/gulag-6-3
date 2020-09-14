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
	message_page = fs.readFileSync(path.join(__dirname, '/public/message.html') ,'utf8'),
	httpsAgent = new https.Agent({
		rejectUnauthorized: false,
		keepAlive: true,
	}),
	httpAgent = new http.Agent({
		rejectUnauthorized: false,
		keepAlive: true,
	}),
	message_data = {
		200: 'OK',
		400: 'Bad request',
		401: 'Unauthorized',
		402: 'Payment required',
		403: 'Access forbidden',
		404: 'Cannot %METHOD% %URL%',
		503: 'Service Unavailable',
	},
	gen_msg = (res, code, message, title)=>{
		var preset_message = message_data[code].replace('%METHOD%', res.req.method).replace('%URL%', res.req.url),
			exposed_vars = {
				title: title || code,
				reason: message || preset_message,
			};
		
		if(!res.headersSent){
			res.set('content-type', 'text/html');
			res.status(code)
		
			res.send(message_page.replace(/\{(\w+)\}/g, (match, p1) => {
				if(exposed_vars[p1])return exposed_vars[p1]
				else return 'undefined'
			}));
		}else return;
	},
	skip_header_regex = /(?:x-|cf-|strict-transport|content-security|content-encoding|host)/i,
	validURL = url => {
		try{ return new URL(url)
		}catch(err){ return null }
	},
	randomIP = ()=>{
		return (Math.floor(Math.random() * 255) + 1)+'.'+(Math.floor(Math.random() * 255))+'.'+(Math.floor(Math.random() * 255))+'.'+(Math.floor(Math.random() * 255))
	},
	addproto = url => (!/^(?:f|ht)tps?\:\/\//.test(url)) ? 'https://' + url : url,
	ready = ()=>{
		if(config.webserver.listenip=='0.0.0.0' || config.webserver.listenip=='127.0.0.1')config.webserver.listenip='localhost';
		var msg = `Listening on ${config.webserver.ssl ? 'https' : 'http'}://${config.webserver.listenip}:${worker_data.port}`;
		process.send({ type: 'started', msg: msg });
	},
	btoa = (str, encoding = 'base64') => Buffer.from(str, 'utf8').toString(encoding),
	atob = (str, encoding = 'base64') => Buffer.from(str, encoding).toString('utf8'),
	proxify_url = (req_full_url, pm_url, url, encode = true)=>{
		if(typeof url != 'string')return url; // if the url given isnt a string, we cant modify it
		
		if(url.match(/^(?=moz-|blob:|javascript:|data:|about:)/gi))return url; // data urls
		
		// //www.domain.tld => https://www.domain.tld
		url = url.replace(/^\/{2}/gi, 'https://');
		
		var pmDirectory = pm_url.href.replace(/(.*?\/)[^\/]*?$/gi, '$1'); // https://domain.tld/directory/page.html => https://domain.tld/directory/
		
		//   /page.html => /https://www.domain.tld/page.html
		
		url = url.replace(/^\/(?!.{3,}:\/\/)\/?/gi, pm_url.origin + '/'); 
		
		/* bruh => /https://www.domain.tld/test
		// notice the lack of a / at the start
		*/
		
		if(!url.match(/.{3,}:\/\//gi))url = pmDirectory + url
		
		/* url sometimes ends up as like https://localhost:7080/DASH_360.mp4 when it should NOT include the origin url inside of the
		// base64 crap done below below so it should work when replacing it with the pm_url's origin
		*/
		
		url = url.replace(new RegExp('^' + req_full_url.origin.replace(/\//g, '\\/').replace(/\./g, '\\.') , 'gi'), pm_url.origin);
		
		// url should be formed nicely so just like base64ify it
		
		if(encode && url.length <= 1024)url = req_full_url.origin + '/?pm_url=' + btoa(url)
		else url = req_full_url.origin + '/' + url
		
		return url
	},
	rewrite_body = (data, res) => {
		if(data.send_data.constructor == Buffer)data.send_data = data.send_data.toString('utf8');
		
		// youtube apparently needs the servers ip in the page so only change ip on every other page
		if(data.url.hostname != 'www.youtube.com'){
			data.send_data.replace(new RegExp(worker_data.ip, 'gi'), randomIP());
			data.send_data.replace(new RegExp(btoa(worker_data.ip), 'gi'), btoa(randomIP()));
		}
		
		if(!data.contentType.startsWith('text/html'))return;
		
		var preload_script_data = { // stuff we send to the script
				pm_url: data.url.href,
				pm_session: res.req.session.pm_session,
				pm_session_url: res.req.session.pm_session_url,
				urlrewrite_date: fs.statSync('./public/pm-cgi/js/urlrewrite.js').mtimeMs,
				inject_date: fs.statSync('./public/pm-cgi/js/inject.js').mtimeMs,
			},
			url_dir = data.url.href.replace(/(.*?\/)[^\/]*?$/gi, '$1'), // https://domain.tld/directory/page.html => https://domain.tld/directory/
			rewrites = [
				// replace "//www.domain.com" => "https://www.domain.com"
				[/(\s[\D\S]*?\s*?=\s*?(\"|\'))\/{2}([\s\S]*?)\2/gi, '$1https://$3$2'],
				
				// strange attribute names
				[/(xlink:)(href)/gi, '$2'],
				
				// /websitelocalfilething => https://domain.tld/websitelocalfilething 
				[/(\s{1,})((?:target|href|data-href|data-src|src|srcset|data|action)\s*?=\s*?(?:"|'))((?!data:|javascript:)\/[\s\S]*?)((?:"|'))/gi, (match, p1, p2, p3, p4)=>{
					var rurl = data.url.origin + p3;
					
					return p1 + p2 + rurl + p4
				}],
				
				// ./img/bruh => https://domain.tld/directory/img/bruh
				[/(\s{1,})((?:target|href|data-href|data-src|src|srcset|data|action)\s*?=\s*?(?:"|'))\.\/([\s\S]*?)((?:"|'))/gi,'$1$2' + url_dir + '$3$4'],
				
				// this does all the proxying magic, "https://www.domain.tld => "https://localhost/https://www.domain.tld
				[/(?<!(?:xmlns|xmlns:web)\s*?=)("|\')(?=https?:\/\/)(.*?)\1/gi, (match, p1, p2, p3, offset, string)=>{
					var quote = p1,
						toproxy_url = p2,
						output = quote + toproxy_url + quote;
					
					if(toproxy_url.startsWith(res.req.full_url.origin))return output; // dont reproxy urls
					
					toproxy_url = proxify_url(res.req.full_url, data.url, toproxy_url, false);
					
					output = quote + toproxy_url + quote;
					
					return output
				}],
				
				// integrity and nonce cant be done
				[/ (integrity|nonce)[\s]*?=[\s]*?".*?" ?/gi, ''],
				[/(?:document|window|location|window.location|document.location)(\.(?:href|host|hostname|pathname|port|protocol|hash|search))/gi, 'pm_url$1'],
				
				// replace title with Right-To-Left Override
				[/<title.*?>.*?<\/ ?title>/gi, '<title>\u202E</title>'],
				
				// replace favicon with default one
				[/("|').[^"']*\.ico(?:\?.*?)?("|')/gi, '$1/favicon.ico$2'],
				
				// prevent popups, newtabs, or redirecting iframes
				[/("|')_(?:blank|top|parent)\1/gi, '$1_self$1'],
				
				// inject code
				[/(<script(?:.*?)>(?:(?!<\/script>)[\s\S])*<\/script>|<\/head>)/i, '<script data="' + encodeURI(btoa(JSON.stringify( preload_script_data, null ))) + '" src="/pm-cgi/js/preload.js?' + fs.statSync('./public/pm-cgi/js/preload.js').mtimeMs + '"></script>$1'],
				
				// replace like the session url is equal to https://domain.tld/ and replace all links to the session url with the /ses/
				res.req.session.pm_session ? [new RegExp(`("|')${ res.req.full_url.origin }\\/${ res.req.session.pm_session_url }(.*?)\\1`,'gi'), '$1/ses/$2$1'] : null,
				
				// debug info
				res.req.query.debug == 'true' ? [/<\/body>/gi, `
				<!-- [POWERMOUSE STATS]
				Worker PID: ${process.pid}
				Port: ${worker_data.port}
				Host: ${os.hostname()}
				--></body>`.replace(/\t/g, '')] : null,
				
				// API for discord.com is strange but discordapp.com works 
				data.url.host == 'discord.com' ? [/API_ENDPOINT: '\/{2}discord.com\/api'/gi, "API_ENDPOINT: '" + res.req.full_url.origin + "/https://discordapp.com/api'"] : null,
				data.url.host == 'discord.com' ? [/<\/body>/gi, '<script type="text/javascript" src="/pm-cgi/js/discord.js"></script>'] : null,
				
				data.contentType.startsWith('text/css') ? [/((?::\s*|\s)url\()("|')?(?=[^\+])([\s\S]*?)\2(\))/gi, (match, p1, p2, p3, p4, offset, string) => {
					var part = p1,
						quote = (p2 == undefined ? '' : p2),
						toproxy_url = p3,
						end_part = p4;
					
					toproxy_url = proxify_url(res.req.full_url, data.url, toproxy_url, true)
					
					return part + quote + toproxy_url + quote + end_part
				}] : null,
			];
		
		rewrites.filter(entry => entry).forEach(entry => {
			data.send_data = data.send_data.replace(entry[0], entry[1]);
		});
		
		try{ // ATTEMPT to minify content, if this fails then it is not needed
			if(data.contentType.startsWith('text/css'))htmlMinify.minify('<style>' + data.send_data + '</style>', {minifyCSS: true}).replace(/(?:^<style>|<\/style>$)/gi,'');
			else data.send_data = htmlMinify.minify(data.send_data, {minifyCSS: true, minifyJS: true});
		}catch(err){}
	},
	compress_data = async data => {
		try{switch(data.contentType.match(/^[^\s\/]*?\/([^\s\/;]*)/gi)[0]){
			// case'image/webp': break // cannot double-compress without losing alpha
			case'image/jpeg':
			case'image/jpg':
				
				data.send_data = await image.jpeg({ quality: 7 })(data.send_data);
				
				break
			case'image/png':
				
				data.send_data = await image.webp({ quality: 25, alphaQuality: 75 })(data.send_data);
				
				break
		}}catch(err){}
	},
	proxyAgent = config.proxy.vpn.enabled ? new socksProxyAgent('socks5://' + config.proxy.vpn.socks5) : null,
	sessions = worker_data = {};

process.on('message',(data)=>{
	switch(data.type){
		case'worker_data':
			
			worker_data = data
			
			// start up server stuff
			listen = config.webserver.listenip;
			if(config.webserver.ssl == true){
				server = https.createServer(ssl, app).listen(worker_data.port, config.webserver.listenip,ready);
			}else{
				server = http.createServer(app).listen(worker_data.port, config.webserver.listenip,ready);
			}
			
			// these are all infinity so its reasonable to have a ton of = things
			server.maxConnections = http.globalAgent.maxSockets = https.globalAgent.maxSockets = Infinity
			
			server.timeout = server.keepAliveTimeout = 15000
			
			
			require('./ws.js')(server);
			
			worker_data.useragents = eval(worker_data.useragents);
			
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
	
	req.full_url = new URL(tmp_data.url_proto + '://' + req.get('host') + req.originalUrl);
	
	tmp_data.sid = req.cookies['pm_connect.sid']
	tmp_data.cookie = { maxAge: 900000, httpOnly: true/*, domain: req.full_url.host.match(/\..{2,3}(?:\.?.{2,3}).*?$/gim)*/, secure: true, sameSite: 'Lax' }
	
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

app.use('/prox', (req, res, next)=>{
	var url = req.body.url || req.query.url;
	
	if(!validURL(addproto(url)))return gen_msg(res, 400, 'Specify a url in your request');
	else return res.redirect(302, '/' + validURL(addproto(url)).href);
});

app.get('/stats', (req, res, next)=>{
	res.status(200);
	res.contentType('application/json');
	res.send(JSON.stringify({ uptime: process.uptime().toString() }))
});

app.post('/session-url', (req,res,next)=>{
	// check for no url at all or a bad url
	if(req.body.url == null || (typeof req.body.url == 'string' && req.body.url.length == undefined))return gen_msg(res, 400, 'Specify a url in your post body');
	
	req.session.pm_session = true
	req.session.pm_session_url = req.body.url
	
	res.redirect(302, '/ses/');
});

app.use(async (req,res,next)=>{
	if((!req.query.pm_url && fs.existsSync(path.join(public_dir, req.full_url.pathname))) || req.query.ws)return next()
	else if(req.full_url.pathname == '/clear-session'){
		Object.entries(req.session).forEach(e=>{ // clear all session data
			req.session[e[0]] = null
		});
		return gen_msg(res, 200, 'Successful', 'Session data cleared');
	}else if(req.full_url.pathname.match(/^\/{3}/gi))return res.redirect(302, req.full_url.pathname.replace(/^\/{3}/gi, '/https://')); //, //domain.tld => https://domain.tld
	else if(config.proxy.ban_bots && worker_data.useragents.test(req.get('user-agent')))return gen_msg(res, 403, 'bad bot!'); // request is most likely from a bot
	
	var data = {
			contentType: 'text/plain',
			send_data: null,
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
				agent: _parsedURL => config.proxy.vpn.enabled ? proxyAgent : _parsedURL.protocol == 'http:' ? httpAgent : httpsAgent,
			},
			return_headers: {},
			clearVariables: ()=> Object.keys(data).forEach(key => delete data[key]),
			url: '',
		};
	
	/* ignore if the url is /https:/domain.tld
	// and not /https://domain.tld
	*/
	
	req.url = req.url.replace(/^(\/?)http(s?):\/(?!\/)/gi, '$1http$2://');
	
	if(req.query.pm_url){
		var tmp_pm_url = validURL(atob(req.query.pm_url)) || validURL(req.query.pm_url);
		
		// /?pm_url=Z28gYXdheSBub29i (base64) urls
		data.url = tmp_pm_url ? new URL(tmp_pm_url) : '';
	}else if(req.full_url.pathname.startsWith('/ses/') && !req.session.pm_session){
		// visiting /ses/ without a session url
		return gen_msg(res, 403, 'You need a url session to access this page.')
	}else if(req.full_url.pathname.startsWith('/ses/'))try{
		// session url is set properly
		var session_url = new URL(req.session.pm_session_url);
		
		data.url = new URL(session_url.origin + '/' + req.full_url.pathname.replace(/^\/ses\//gi, ''));
	}catch(err){
		return gen_msg(res, 400, err.message);
	}else try{
		// visting url like /https://domain.tld/page.html, we remove the / from the start and have a url to proxy
		data.url = new URL(req.full_url.href.substr(req.full_url.origin.length + 1));
	}catch(err){
		/* fallback to req.sesison.ref
		// req.session.ref is only set when the content-type is text/html
		*/
		
		if(req.session.ref){
			var ref = new URL(req.session.ref),
				newURL = '/' + ref.origin + req.url;
			
			// /page-we-have-not-rewritten => /https://domain.tld/page-we-have-rewritten
			return res.redirect(307, newURL);
		}else{
			return gen_msg(res, 404, err.message);
		}
	}
	
	// if all went good, url should be an instance of URL
	
	// not a special url modifying mode
	if(!req.session.pm_session){
		// checking the url will give a different result than the one in the request
		if(req.url.substr(1 + data.url.origin.length) != data.url.href.substr(data.url.origin.length)){
			return res.redirect(302, req.full_url.origin + '/' + data.url.href) && data.clearVariables();
		}
	}
	
	/* discord junk
	// redirect https://discord.com/ or https://discord.com/new to https://discord.com/login until discord homepage can be proxied
	// prevent casual email password login as it will require a captcha which this proxy cannot do
	*/
	
	if(data.url.hostname == 'discordapp.com' && data.url.pathname == '/api/v8/auth/login')return res.status(400).contentType('application/json; charset=utf-8').send(JSON.stringify({ email: 'Use the QR code scanner or token login button to access discord' }));
	
	if(data.url.pathname.match(/^(?:\/|\/new)$/gi) && data.url.hostname == 'discord.com')return res.redirect(307, req.full_url.origin + '/' + data.url.origin + '/login') && data.clearVariables();
	
	/* make a dns lookup to the url hostname, if it resolves to a private ip address such as 192.168.0.1 then
	** we can prevent the request
	** additionally, this can handle invalid urls too giving an getaddrinfo ENOTFOUND error
	** instead of node-fetch giving an error
	*/
	
	if(data.url.host)await dns.lookup(data.url.host, (err, address, family) => {
		if(err)switch(err.errno){
			case -3008:
				
				return gen_msg(res, 400, 'DNS lookup failed for host: ' + data.url.host + ' (' + err.code + ')') && data.clearVariables()
				
				break
			default:
				
				return gen_msg(res, 400, err.message) && data.clearVariables()
				
				break
		}else if(!config.proxy.private_ips && address.match(/^(?:192.168.|172.16.|10.0.|127.0)/gi))return gen_msg(res, 403, 'Please don\'t abuse this service! (' + data.url.host + ' points to ' + address + ')');
	});
	
	// pass the req.body as a string as most server sided scripts will parse
	if(req.method.match(/post|patch/gi))data.fetch_options['body'] = req.raw_body;
	
	// handle request headers
	
	Object.entries(req.headers).forEach(entry =>{
		var name = entry[0].toLowerCase(),
			value = entry[1];
		
		// do not include cdn- or cloudflare- headers
		
		if(!value.includes(data.url.host) && !name.match(skip_header_regex))data.fetch_headers[name] = value;
	});
	
	if(data.url.host == 'matchmaker.krunker.io'){
		var game_url = data.fetch_headers.krunker_game_url == null ? '' : data.fetch_headers.krunker_game_url;
		
		if(data.fetch_headers.origin)data.fetch_headers.origin = data.fetch_headers.origin.replace('https://kru2.sys32.dev', 'https://krunker.io');
		if(data.fetch_headers.referer)data.fetch_headers.referer = data.fetch_headers.referer.replace('https://kru2.sys32.dev', 'https://krunker.io');
	}else{
		if(data.fetch_headers['referrer'])data.fetch_headers['referrer'] = data.url.href
		if(data.fetch_headers['referer'])data.fetch_headers['referer'] = data.url.origin
		if(data.fetch_headers['origin'])data.fetch_headers['origin'] = data.url.origin
	}
	
	data.fetch_options['headers'] = data.fetch_headers;
	
	try{
		data.response = await fetch(data.url, data.fetch_options);
		data.send_data = await data.response.buffer();
	}catch(err){
		if(res.headersSent)return;
		else switch(err.code){
			case'HPE_HEADER_OVERFLOW':
				// clear all cookies
				Object.entries(req.cookies).forEach(entry => {
					res.clearCookie(entry[0]);
				});
				
				// reload with updated headers
				return res.redirect(req.originalUrl);
				
				break
			default:
				
				return gen_msg(res, 400, err.message);
				
				break
		}
	}
	
	// response html, headers, status, etc.. have already been sent, stop stuff from here
	if(res.headersSent)return;
	
	// redirect has happened at least once
	if(req.session.pm_session != true && data.response.redirected == true)return res.redirect(307, '/' + data.response.url);
	else if(req.session.pm_session == true && data.response.redirected == true){ // session-mod eredirect
		var new_url = new URL(data.response.url);
		
		// need to set a new url in the session of the origin has changed from a redirect
		if(new_url.origin != req.session.pm_session_url)req.session.pm_session_url = new_url.origin
		
		// turn /https://domain.tld/page.html into  /ses/page.html as the origin has changed
		return res.redirect(307, '/ses/' + new_url.href.substr(new_url.origin.length + 1));
	}
	
	data.response.headers.forEach((value, header)=>{
		if(!skip_header_regex.test(header)){
			res.set(header, value);
			
			if(header.toLowerCase().trim() == 'content-type')data.contentType = value
		}
	});
	
	if(/^20/.test(data.response.status) && data.contentType.startsWith('text/html'))req.session.ref = data.url.href;
	
	res.status(data.response.status);
	
	// check if mime.getType will return something with font/ to avoid proxying fonts
	
	if(data.contentType.startsWith('application/x-shockwave-flash') || (mime.getType(data.url.href) != null && mime.getType(data.url.href).match(/^(?:font|audio|video)\//gi))){
		return res.set('Cache-Control','max-age=31536000') && res.send(data.send_data);
	}
	
	if(data.contentType.startsWith('image')){
		res.set('Cache-Control','max-age=31536000');
		
		await compress_data(data);
	}
	
	if(data.contentType.match(/^(text)\//i)){
		// convert buffer to string
		rewrite_body(data, res);
	}
	
	// res.set('Access-Control-Allow-Origin', '*');
	
	try{
		res.send(data.send_data);
		data.clearVariables();
	}catch(err){
		console.error(err);
		res.send(err.code);
	}
});

app.use('/', express.static(public_dir));