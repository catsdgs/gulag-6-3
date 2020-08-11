const fs = require('fs'),
	process = require('process'),
	threads = require('worker_threads'),
	fetch = require('node-fetch'),
	express = require('express'),
	websocket = require('ws'),
	app = express(),
	path = require('path'),
	mime = require('mime'),
	util = require('util'),
	cookieParser = require('cookie-parser'),
	streamPipeline = util.promisify(require('stream').pipeline),
	https = require('https'),
	http = require('http'),
	bodyParser = require('body-parser'),
	htmlMinify = require('html-minifier'),
	compression = require('compression'),
	os = require('os'),
	crypto = require('crypto'),
	dns = require('dns'),
	image = {
		jpeg: require('imagemin-mozjpeg'),
		webp: require('imagemin-webp'),
	},
	socksProxyAgent = require('socks-proxy-agent');
var config = JSON.parse(fs.readFileSync('config.json','utf-8')),
	args = process.argv.splice(2),
	ssl = {key: fs.readFileSync('ssl/default.key','utf8'),cert:fs.readFileSync('ssl/default.crt','utf8')},
	msgPage = page = fs.readFileSync(__dirname+'/public/error.html','utf8'),
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
				return res.send(msgPage.replace('%TITLE%','Bad domain').replace('%REASON%', (value || `Cannot ${method} ${url}`) ));
				break
			case 697:
				res.status(500)
				return res.send(msgPage.replace('%TITLE%',value.code).replace('%REASON%', value.message ));
				break
			case 400:
				res.status(code)
				return res.send(msgPage.replace('%TITLE%',code).replace('%REASON%', (value || 'Bad request') ));
				break
			case 403:
				res.status(code)
				return res.send(msgPage.replace('%TITLE%',code).replace('%REASON%', (value || 'Access forbidden') ));
				break
			case 500:
				res.status(code)
				return res.send(msgPage.replace('%TITLE%',code).replace('%REASON%', (value || 'A server is unable to handle your request') ));
				break
			case 404:
			default:
				res.status(code);
				return res.send(msgPage.replace('%TITLE%',code).replace('%REASON%',`Cannot ${method} ${url}`));
				break
		}
	}catch(err){}},
	validURL = (url)=>{
		try{
			return new URL(url)
		}catch(err){
			return null
		}
	},
	randomIP = ()=>{
		return (Math.floor(Math.random() * 255) + 1)+"."+(Math.floor(Math.random() * 255))+"."+(Math.floor(Math.random() * 255))+"."+(Math.floor(Math.random() * 255))
	},
	getDifference = (begin,finish)=>{
		var ud=new Date(finish-begin);
		var s=Math.round(ud.getSeconds());
		var m=Math.round(ud.getMinutes());
		var h=Math.round(ud.getUTCHours());
		return `${h} hours, ${m} minutes, ${s} seconds`
	},
	addproto = (url)=>{
		if (!/^(?:f|ht)tps?\:\/\//.test(url))url = "https://" + url;
		return url;
	},
	similar = (a,b)=>{
		var equivalency = 0;
		var minLength = (a.length > b.length) ? b.length : a.length;    
		var maxLength = (a.length < b.length) ? b.length : a.length;    
		for(var i=0;i<minLength;i++)if(a[i]==b[i])equivalency++;
		var weight = equivalency / maxLength;
		return (weight * 100);
	},
	ready = ()=>{
		if(config.webserver.listenip=='0.0.0.0' || config.webserver.listenip=='127.0.0.1')config.webserver.listenip='localhost';
		var msg=`Listening on ${config.webserver.ssl ? 'https' : 'http'}://${config.webserver.listenip}:${workerData.port}`;
		threads.parentPort.postMessage({type:'log', id: threads.threadId, value: msg});
	},
	btoa=(str,encoding)=>{
		return Buffer.from(str,'utf8').toString(( typeof encoding == 'undefined' ? 'base64' : encoding))
	},
	atob=(str,encoding)=>{
		return Buffer.from(str, ( typeof encoding == 'undefined' ? 'base64' : encoding)).toString('utf8')
	},
	proxyAgent = (config.proxy.vpn.enabled == true ? new socksProxyAgent('socks5://' + config.proxy.vpn.socks5) : null)
	sessions = new Object(),
	workerData = {
		ip: threads.workerData.ip,
		tlds: threads.workerData.tldRegex,
		port: threads.workerData.port,
		tldList: threads.workerData.tldList,
	}

threads.parentPort.on('message',(data)=>{
	switch(data.type){
		case'update_session':
			sessions = data.sessions;
			break
		default:
			
			break
	}
});

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(compression({ level: 2 }));

// start up server stuff
listen = config.webserver.listenip;
if(config.webserver.ssl==true)server = https.createServer(ssl,app).listen(workerData.port, config.webserver.listenip,ready);
else server = http.createServer(app).listen(workerData.port, config.webserver.listenip,ready);

// these are all infinity so its reasonable to have a ton of = things
server.maxConnections = http.globalAgent.maxSockets = https.globalAgent.maxSockets = Infinity

require('./ws.js')(server);

app.use((req,res,next)=>{
	// hacky implementation of session stuff
	// this will add request.session ( a proxy thing acting as an object so it can see whats being added to push to the centeral script )
	
	var url_proto = (config.webserver.ssl == true ? 'https' : 'http');
	
	// repl.it support for its proxypass usage on nodejs apps
	if(process.env.REPL_OWNER != null)url_proto = 'https' 
	
	req.fullURL = new URL(url_proto + '://' + req.get('host') + req.originalUrl);
	
	var sid = req.cookies['pm-connect.sid'],
		cookie = { maxAge: 900000, httpOnly: true/*, domain: req.fullURL.host.match(/\..{2,3}(?:\.?.{2,3}).*?$/gim)*/, secure: true, sameSite: 'Lax' };
	
	/* note: remove the domain: blah stuff when testing on an insecure, rather https:// with that yellow lock icon thing on firefox showing up, makes the sid go out of control */
	
	if(typeof sid == 'undefined' || sid.length <= 7){
		while(true){
			sid=crypto.randomBytes(32).toString('hex');
			if(sessions[sid] != null)continue;
			break;
		}
	}
	
	res.cookie('pm-connect.sid', sid, cookie);
	
	res.cookie('pm-server', os.hostname().substr(0,4).toLowerCase(), cookie);
	
	if(sessions[sid] == null)sessions[sid]={}
	
	sessions[sid].__lastAccess = Date.now();
	sessions[sid].sid = sid;
	sessions[sid].cookie = cookie;
	
	req.session = new Proxy(sessions[sid], {
		set: (target, prop, value)=>{
			Reflect.set(target, prop, value);
			threads.parentPort.postMessage({type:'store_set', sid: target.sid, session: target });
		}
	});
	
	return next();
});

app.get('/pm-cgi/',(req,res)=>{
	return res.redirect('/');
	
	// this is a static stuff directory so redirect out of it for ease 
});

app.get('/uptime',(req,res,next)=>{
	var uptimeMS = process.uptime()
	
	// process.uptime() gives the amount of seconds
	
	res.status(200);
	res.contentType('text/html');
	res.send(uptimeMS.toString());
});

app.get('/suggestions',(req,res)=>{ // autocomplete urls
	if(typeof req.query.input != 'string' || req.query.input == '')return genMsg(req,res,400,'Invalid domain input/type');
	var suggestions=[],input=req.query.input,index=0,tldCheck='',sortedList={},matched=input.match(/\..{2,3}(?:\.?.{2,3})?/gim);
	
	res.status(200);res.contentType('application/json');
	
	if(matched===null || matched==='')return res.send(JSON.stringify(['com','net','org','io','dev'])); else tldCheck=matched[0].substr(1);
	
	workerData.tldList.forEach((e,i)=> sortedList[similar(tldCheck,e)] = e);
	
	var bruvList=Object.entries(sortedList).sort(((a,b)=>{
			return a[0] - b[0];
	})).reverse();
	
	bruvList.forEach((e,i)=>{
		if(index>5)return;
		index++;
		suggestions.push(e[1]);
	});
	return res.send(JSON.stringify(suggestions));
});

app.get('/linkGen',(req,res,next)=>{
	var file=fs.readFileSync(path.join(__dirname, 'public/linkGen.html'));
	res.status(200);
	res.contentType('text/html');
	return res.send(file);
});

var urlData=JSON.parse(fs.readFileSync('urlData.json','utf8')),
	writeURLs=(()=>{
		var perhaps=JSON.parse(fs.readFileSync('urlData.json','utf8'));
		if(urlData == perhaps)return false; // the url data hasnt changed
		// if the above hasnt done a thing then code continues
		fs.writeFileSync('urlData.json',JSON.stringify(urlData, null, '\t'),'utf-8');
		// data success
	}),
	reloadURLs=(()=>{
		// we read file stuff now
		var perhaps=JSON.parse(fs.readFileSync('urlData.json','utf8'));
		if(urlData != perhaps)urlData=perhaps;
	}),
	urlExpire=10800000;
	// 3000 = 3 seconds, 10000 = 10 seconds, 60000 = 1 minute, 180000 = 3 minutes, 10800000 = 3 hours

app.post('/alias',(req,res,next)=>{
	var url = req.body.url.trim().toLowerCase().replace(/[^a-z0-9.:\/]/gi,''), // replace bad characters
		alias = req.body.alias.trim().toLowerCase().replace(/[^a-z0-9.:\/]/gi,''), // replace more bad characters!
		sideNote=''; // additional user message for later if needed
	try{
		url=new URL(url).origin
	}catch(err){
		res.status(400);
		res.contentType('text/html');
		return res.send(msgPage.replace('%TITLE%',err.code).replace('%REASON%',err.message));
	}
	
	url=addproto(url); // this is done on the client too for checking but is needed here
	reloadURLs(); // reload url list
	
	// Alias errors
	
	if(alias == '')sideNote=`A random alias had to be generated due to an alias not being specified`;
	if(urlData.some(e=> e.alias.startsWith(alias) || alias.startsWith(e.alias) ) )sideNote=`A random alias had to be generated due to conflicts with other aliases`;
	if(alias.length < 4)sideNote=`The alias specified was shorter than 4 characters so a random one was generated`;
	
	// URL errors
	if(config.directIPs==false && url.match(/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/gi)){
		res.status(400);
		res.contentType('text/html');
		return res.send(page.replace('%TITLE%','Bad URL').replace('%REASON%','Aliases pointing to an IP address are not permitted'));
	}else if(typeof url != 'string'){
		res.status(400);
		res.contentType('text/html');
		return res.send(page.replace('%TITLE%','Bad URL').replace('%REASON%','The URL specified is not a valid string'));
	}else if(!url.match(workerData.tldRegex)){
		res.status(400);
		res.contentType('text/html');
		return res.send(page.replace('%TITLE%','Bad URL').replace('%REASON%','The URL specified was not a valid URL'));
	}
	
	if(alias == '' || alias.length <= 4 || urlData.some(e=> e.alias.startsWith(alias) || alias.startsWith(e.alias) ) ){
		while(true){
			alias = Math.random().toString(36).substring(2, 8) + Math.random().toString(36).substring(2, 8); // random alias
			if( urlData.some(e=>e.value == alias) )continue; // if the new alias has bee found in the url data, try again
			break;
		}
	}
	urlData.push({
		time: Date.now(),
		value: addproto(url),
		alias: alias
	});
	writeURLs();
	res.status(200);
	res.contentType('text/html');
	
	if(sideNote != '')sideNote=`<div class='lbottom'><span id='logMsg'>`+sideNote+`</span></div>`;
	return res.send(msgPage.replace('%TITLE%','Success').replace('%REASON%',`
	<a href="./${req.fullURL.origin}/alias/${alias}"><span>${req.fullURL.origin}/alias/${alias}</span></a> now points to <a href="./${addproto(url)}"><span>${addproto(url)}</span></a>
	${sideNote}
	`));
});

app.use((req,res,next)=>{
	if( !req.url.startsWith('/prox') ||  (req.method=='POST' && !req.body.url) || (req.method=='GET' && !req.query.url) )return next();
	
	var url = addproto((req.method == 'GET' ? req.query.url : req.body.url));
	
	try{
		url=new URL(addproto(url))
	}catch{
		return next() // dont parse bad urls
	}
	
	res.redirect('/'+url.href);
	
	url = null
});

app.use((req,res,next)=>{
	if(req.fullURL.pathname != '/rpm' || (req.method=='POST' && !req.body.url) || (req.method=='GET' && !req.query.url) )return next();
	
	var url = addproto((req.method == 'GET' ? req.query.url : req.body.url));
	
	req.session.pm_session = true
	
	req.session.pm_session_url = url;
	
	res.redirect('/ses/');
	
	url = null
});

app.use(async (req,res,next)=>{
	if(req.query.ws != undefined)return next(); // noo websocket script did not handle 
	
	if(req.query.pm_url == null && (req.fullURL.pathname == '/' || req.fullURL.pathname.match(/^\/pm-cgi.*/) || req.fullURL.pathname == '/favicon.ico'))return next()
	else if(req.fullURL.pathname == '/sesUrl')return res.sendFile(path.join(__dirname + '/public/session.html'))
	else if(req.fullURL.pathname == '/clrSes'){
		req.session.expires = Date.now(); // set it so this session expires quicklyy
		return res.send(msgPage.replace('%TITLE%','Session data cleared').replace('%REASON%', 'All was done with success' ));
	}else if(req.fullURL.pathname.match(/^\/{3}/gi)){ //, //domain.tld => https://domain.tld
		return res.redirect(302, req.fullURL.pathname.replace(/^\/{3}/gi, '/https://') )
	}
	
	var data = {
			contentType: null,
			sendData: null,
			response: null,
			fetch_headers: {
				'cookie': (()=>{
					var tmp = ''
					Object.entries(req.cookies).forEach((e,i)=>{
						tmp+= e[0] + '=' + e[1] + ';'
					});
					return tmp
				})()
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
	
	var tooManyOrigins=new RegExp(`(?:${req.fullURL.origin.replace(/\//g,'\\/').replace(/\./gi,'\\.')}\/|\/\/${req.fullURL.host.replace(/\\./g,'\\.')})`,'gi');
	
	if(req.url.substr(1).match(tooManyOrigins)){
		res.redirect(307, req.url.replace(tooManyOrigins,''));
		return data.clearVariables();
	}
	
	reloadURLs();
	
	var alias_mode=urlData.some(e=>req.url.match(new RegExp(`^/alias/${e.alias}`,'gi')));
	var shor='placeholder', newURL='placeholder', alias_set='placeholder';
	
	if(req.fullURL.pathname.startsWith('/no_proxy/')){
		req.fullURL = new URL(req.fullURL.href.replace(/\/no_proxy\//gi, '/'));
		req.no_proxy = true;
	}
	
	if(req.query.pm_url != null && validURL(atob(req.query.pm_url)) ){
		url = new URL(atob(req.query.pm_url))
	}else if( alias_mode ){ // if a shortened url link matches in the url stuff
		
		urlData.forEach((e,i)=>{
			var regoink=new RegExp(`^\/alias\/${e.alias}`,'gi');
			if(req.fullURL.pathname.match(regoink)){
				shor = e.value; // set shortened to the value found within the url data stuff
				alias_set = e.alias;
				newURL = req.url.replace(regoink,e.value);
				url = new URL(newURL);
				
			}
		});
		
	}else if(req.fullURL.pathname.startsWith('/ses/') ){
		
		if(req.session.pm_session != true)return genMsg(req, res, 403, 'You need a url session to access this page.');
			
		try {
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
	console.log(url.href);
	if(url.href == 'https://discordapp.com/api/v6/auth/login')return res.status(400).contentType('application/json; charset=utf-8').send(JSON.stringify({ email: 'Use the QR code scanner or token login option to access discord' }));
	
	
	if(url.hostname == 'discord.com' && (url.pathname == '/new' || url.pathname == '/')){
		res.redirect(307, req.fullURL.origin + '/' + url.origin + '/login')
		
		return data.clearVariables();
	}
	
	if(!url.hostname.match(workerData.tldRegex))return genMsg(req,res,696);
	
	/* make a dns lookup to the url hostname, if it resolves to a private ip address such as 192.168.0.1 then
	** we can prevent the request
	*/
	
	if(!config.proxy.private_ips && url.host != '')await dns.lookup(url.host, (err, address, family) => {
		if(err){
			genMsg(req, res, 400, err.message);
			
			return data.clearVariables();
		}else if(address.match(/^(?:192.168.|172.16.|10.0.|127.0)/gi)){
			genMsg(req, res, 403, 'please dont try to connect to private ips :(');
			
			return data.clearVariables();
		}
	});
	
	/* check if the url like https://google.com/directory
	** will become https://google.com/directory/ <== notice the slash added
	*/
	
	var poggerUrl = req.url.substr(1).replace(/http(s?):\/([^\/])/gi,"http$1://$2");
	
	if(req.session.pm_session != true && req.no_proxy != true && !alias_mode && poggerUrl != url.href && !req.query.pm_url)return res.redirect(307,'/'+url.href);
	
	// handle post body:
	if(req.method == 'POST')data.fetch_options['body'] = JSON.stringify(req.body, (key, value)=>{ return value} );
	
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
	
	data.fetch_headers['referer'] = url.href
	data.fetch_headers['origin'] = url.origin
	
	data.fetch_options['headers'] = data.fetch_headers;
	
	data.response = await fetch(url, data.fetch_options).catch(err => {
		data.response = null
		
		if(req != null && req.msgShown)return;
		
		switch(err.code){
			case'HPE_HEADER_OVERFLOW':
				Object.entries(req.cookies).forEach((e,i)=>{ // clear all cookies
					res.clearCookie(e[0]);
				});
				
				return res.redirect(req.url);
				
				break
			default:
				
				return genMsg(req,res,697,err);
				
				break
		}
		
	});
	
	if(req.msgShown)return;
	
	if(req.session.pm_session != true && data.response != undefined && data.response.redirected == true){ // redirect has happened at least once
		return res.redirect(307, '/' + data.response.url);
	}else if(req.session.pm_session == true && data.response.redirected == true){
		var tmp = new URL(data.response.url),
			tmp2 = '/ses';
		
		// need to set a new url in the session of the origin has changed from a redirect..
		
		if(tmp.origin != req.session.pm_session_url){
			req.session.pm_session_url = tmp.origin
		}
		
		tmp2 = '/ses/' + tmp.href.substr(tmp.origin.length + 1); // turn /https://discord.com/ae into /ae as the origin has changed
		
		return res.redirect(307, tmp2);
	}
	
	if(typeof data.response == 'undefined' || typeof data.response.buffer != 'function')return; // error should have already been handled at this point so just return
	
	data.sendData = await data.response.buffer();
	
	data.response.headers.forEach((e,i)=>{
		if(i == 'content-type')data.contentType = e; //safely set content-type
	});
	
	if(data.contentType == null)data.contentType = mime.getType(url.href.match(/\.(\w{2,4})/gi));
	
	if(data.contentType == null || typeof data.contentType == 'undefined')data.contentType = 'text/html'; // set to text/html as last ditch effort
	
	if(data.response.status.toString().startsWith('20') && data.contentType.startsWith('text/html') && typeof req.query['pm-origin'] == 'undefined')req.session.ref = url.href;
	req.session.ref = url.href
	
	if(req.fullURL.href.match(/\.wasm$/gi))data.contentType = 'application/wasm'
	
	if(data.sendData.constructor == Buffer){ // if this is a buffer, not string
		if(data.contentType == 'application/x-msdownload' && data.sendData.byteLength <= 0){
			data.contentType = 'text/plain' // dont download 0 byte files
		}
	}
	
	res.contentType(data.contentType);
	res.status(data.response.status);
	
	if(data.contentType.startsWith('application/x-shockwave-flash') || data.contentType.includes('font'))return res.send(data.sendData); // get straight to the font
	
	if(data.contentType.startsWith('image')){
		switch(data.contentType.match(/^[^\s\/]*?\/([^\s\/;]*)/gi)[0]){
			case'image/webp': // cannot double-compress without losing alpha
				
				//  data.sendData = await image.webp({ quality: 25, alphaQuality: 100 })(data.sendData);
				
				break
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
		
		res.set('Cache-Control','max-age=31536000'); // big cache for images
	}
	
	if(data.contentType.startsWith('text/') || data.contentType.startsWith('application/' && req.no_proxy != true) ){
		data.sendData = (()=>{ var output = ''; data.sendData.toString('utf8').split('\n').forEach(e=> output += e + '\n'); return output })(); // convert buffer to string
		
		var regUrlOri=req.fullURL.origin.replace('.','\\.').replace('/','\\/'), // safe way to have url origin in regex
			urlOri=url.origin.replace('.','\\.').replace('/','\\/'), // safe way to have url origin in regex
			regexFullOrigin = req.fullURL.origin.replace('.','\\.').replace('/','\\/'),
			urlDirectory = url.href.replace(/(.*?\/)[^\/]*?$/gi, '$1'); // https://google.com/bruh/ok.html => https://google.com/bruh/
		
		if(data.contentType.startsWith('text/css'))data.sendData = htmlMinify.minify('<style>' + data.sendData + '</style>', {minifyCSS: true, }).replace(/(?:^<style>|<\/style>$)/gi,''); // cool trick to get htmlMinify to minify a css file and have it display correctly
		
		data.sendData = await data.sendData
		// replace window with our modified window variable
		// .replace(/window/gi, 'pm_window')
		// only match document calls, anything with window before it is handled too
		// .replace(/(?<!window\.)document/gi, 'pm_document')
		
		.replace(new RegExp('(:\s*?url\\((?:"|\')?)(?!data:|' + regexFullOrigin + ')([\\s\\S]*?)((?:"|\')?\\))', 'gi'), (match, p1, p2, p3, offset, string)=>{
			if(typeof req.session.ref != 'undefined'){
				uorigin = new URL(req.session.ref).origin;
			}else{
				uorigin = url.origin;
			}
			
			if(p2.match(/^(?!\/|https?:\/\/).*/gi)){ // asset is like url(bg.png) or some lazy crap
				p2 = uorigin  + '/' + p2
			}else if(p2.match(/^\/{2}/gi)){ // asset is something like //domain.tld/assets/bg.png and we want a protocol not pathetic //
				p2 = 'https:' + p2
			}else if(p2.match(/^\//gi)){ // asset is going for like /assets/bg.png
				p2 = uorigin + p2
			}
			
			return p1 + req.fullURL.origin + '/?pm_url=' + btoa(p2) + p3
		})
		;
		
		if(url.hostname != 'www.youtube.com')data.sendData = data.sendData // run this on not youtube links
		.replace(new RegExp(workerData.ip, 'gi'), randomIP())
		.replace(new RegExp(btoa(workerData.ip), 'gi'), randomIP())
		;
		
		if(data.contentType.startsWith('text/html')){
			var preload_script_data = {
				pm_url: url.href,
				pm_session: req.session.pm_session,
				pm_session_url: req.session.pm_session_url,
				alias_mode: alias_mode,
				alias_url: alias_set,
				windowURL_date: fs.statSync('./public/pm-cgi/windowURL.js').mtimeMs,
				inject_date: fs.statSync('./public/pm-cgi/preload.js').mtimeMs,
				
			}
			
			data.sendData = data.sendData
			
			// replace "//bing.com" => "https://bing.com"
			.replace(/(\s[\D\S]*?\s*?=\s*?(\"|\'))\/{2}([\s\S]*?)\2/gi, '$1https://$3$2')
			// older:
			//.replace(/((?:target|href|data-src|src|srcset|data|action)\s*?=\s*?(?:"|'))\/{2}/gi,'$1https://')
			
			// /websitelocalfilething => https://domain.tld/websitelocalfilething 
			.replace(/(\s{1,})((?:target|href|data-href|data-src|src|srcset|data|action)\s*?=\s*?(?:"|'))((?!data:|javascript:)\/[\s\S]*?)((?:"|'))/gi,'$1$2' + url.origin + '$3$4')
			
			// ./img/bruh => https://domain.tld/directory/img/bruh
			.replace(/(\s{1,})((?:target|href|data-href|data-src|src|srcset|data|action)\s*?=\s*?(?:"|'))\.\/([\s\S]*?)((?:"|'))/gi,'$1$2' + urlDirectory + '$3$4')
			
			// this does all the proxying magic!!! "https://otherdomain.tld => "https://localhost/https://otherdomain.tld
			.replace(new RegExp('("|\')(?=https?:\\/\\/)(?!' + regexFullOrigin + ')(.*?)\\1', 'gi'), (match, p1, p2, p3, offset, string)=>{
				var quote = p1,
					url = p2,
					output = '',
					url_obj = new Object(); // placeholder
				
				try{ url_obj = new URL(url) } // very easy to access url parts now
				catch(err){}
				
				// a blank slate, very nice, what else could be done?
				
				/*
				// base64 encoding
				
				var new_host = encodeURIComponent(btoa(url_obj.hostname));;
				
				url = url.replace(url_obj, new_host);
				*/
				
				output = quote + req.fullURL.origin + '/' + url + quote;
				
				return output
			})
			.replace(/ (integrity|nonce)[\s]*?=[\s]*?".*?" ?/gi,'') // integrity and nonce cant be used 
			.replace(/(\.integrity[\s]*?=[\s]*?)("|')([\s\S]*?)\2/gi, '$1null')
			.replace(/(?:document|window|location|window.location|document.location)(\.(?:href|host|hostname|pathname|port|protocol|hash|search))/gi,'pm_url$1')
			// pm url should be defined in a script somewhere
			
			// empty title thing
			// .replace(/<title.*?>.*?<\/ ?title>/gi,'<title>‮</title>')
			.replace(/("|').[^"']*\.ico(?:\?.*?)?("|')/gi,'$1/favicon.ico$2')
			.replace(/ ?onmousedown="return rwt\(this,.*?"/gi,'')
			.replace(/("|')_(?:blank|top|parent)\1/gi,'$1_self$1')
			.replace(/(<(?:iframe|object)\s*src=("|'))((?:(?!\?)[\s\S])*?)(?:\2)/gi,'$1$3?pm-origin='+btoa(url.host)+'$2') // this regex is for strings without the ? in it
			.replace(/(<(?:iframe|object)\s*src=("|'))((?:(?!&pm-origin=)[\s\S])*?)(?:\2)/gi,'$1$3&pm-origin='+btoa(url.host)+'$2') // this regex for the strings without the &pm-origin= inside of it
			.replace(new RegExp(`(?:${req.fullURL.origin}|${url.origin})/data:`,'gi'),'data:') // fix data urls last
			.replace(/(<script(?:.*?)>(?:(?!<\/script>)[\s\S])*<\/script>|<\/head>)/i, '<script data="' + encodeURI(btoa(JSON.stringify( preload_script_data, null ))) + '" src="/pm-cgi/preload.js?' + fs.statSync('./public/pm-cgi/preload.js').mtimeMs + '"></script>$1')
			.replace(new RegExp(`${regUrlOri}\/\.\/`,'gi'),`./`)
			;
			
			if(alias_mode){
				// replace reference to alias URL with alias
				
				data.sendData = data.sendData.replace(new RegExp(`("|')(?:${ req.fullURL.origin })?\/${shor}(.*?)("|')`,'gi'), (match, p1, p2, p3, offset, string)=>{
					var quote = p1,
						non_proxied_url = p2;
					
					return p1 + req.fullURL.origin + '/alias/' + alias_set + non_proxied_url + quote
				});
			}else if(req.session.pm_session){
				// replace like the session url is equal to https://discord.com/ and replace all links to the session url with the /ses/
				data.sendData = data.sendData.replace(new RegExp(`("|')${ req.fullURL.origin }\\/${ req.session.pm_session_url }(.*?)\\1`,'gi'),'$1/ses/$2$1');
			}
			
			// on cloudflare checks, inform the user we cant proxy this page 
			if(data.sendData.includes('cf-browser-verification cf-im-under-attack'))data.sendData=data.sendData
			.replace(/<\/body>/gi,'  <script type="text/javascript" src="/pm-cgi/cloudflare.js"></script>\n</body>')
			.replace(/<\/head>/gi,'<link rel="stylesheet" href="/pm-cgi/cloudflare.css">\n</head>');
			
			if(typeof req.query.debug == 'string' && req.query.debug == 'true')data.sendData=data.sendData.replace(/<\/body>/gi,`
			<!-- [POWERMOUSE STATS]
			Worker: ${threads.threadId}
			Port: ${workerData.port}
			Host: ${os.hostname()}
			--></body>`.replace(/\t/g, ''));
			
			switch(url.host){
				case'discord.com':
					data.sendData=await data.sendData // hacky discord support
					// API for discord.com is strange but discordapp.com works 
					.replace(`API_ENDPOINT: '//discord.com/api'`,`API_ENDPOINT: '/https://discordapp.com/api'`)
					.replace(/<\/body>/gi,`<script type='text/javascript' src='/pm-cgi/discord.js'></script>`)
					;
					break;
				default:break;
			}
			try{ data.sendData=htmlMinify.minify(data.sendData, {minifyCSS: true, minifyJS: true});
			}catch(err){}
		}
	}
	
	res.send(data.sendData);
	
	return data.clearVariables();
});

app.use('/', express.static(path.join(__dirname, 'public')));