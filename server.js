const fs=require('fs'),
	process = require('process'),
	threads=require('worker_threads'),
	fetch=require('node-fetch'),
	express=require('express'),
	websocket=require('ws'),
	app=express(),
	path=require('path'),
	mime=require('mime'),
	util=require('util'),
	cookieParser=require('cookie-parser'),
	streamPipeline=util.promisify(require('stream').pipeline),
	https=require('https'),
	http=require('http'),
	bodyParser=require('body-parser'),
	htmlMinify=require('html-minifier'),
	compression=require('compression'),
	os=require('os'),
	crypto = require('crypto'),
	dns = require('dns'),
	socksProxyAgent = require('socks-proxy-agent');
var config=JSON.parse(fs.readFileSync('config.json','utf-8')),
	args=process.argv.splice(2),
	ssl={},tt='',
	msgPage=page=fs.readFileSync(__dirname+'/public/error.html','utf8');
	httpsAgent = new https.Agent({
		rejectUnauthorized: false,
		keepAlive: true,
	}),
	httpAgent = new http.Agent({
		rejectUnauthorized: false,
		keepAlive: true,
	}),
	genMsg=((req,res,code,value)=>{ try{
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
	}catch(err){} }),
	validURL = (url)=>{
		try{
			return new URL(url)
		}catch(err){
			return null
		}
	},
	randomIP=(()=>{
		return (Math.floor(Math.random() * 255) + 1)+"."+(Math.floor(Math.random() * 255))+"."+(Math.floor(Math.random() * 255))+"."+(Math.floor(Math.random() * 255))
	});
	getDifference=((begin,finish)=>{
		var ud=new Date(finish-begin);
		var s=Math.round(ud.getSeconds());
		var m=Math.round(ud.getMinutes());
		var h=Math.round(ud.getUTCHours());
		return `${h} hours, ${m} minutes, ${s} seconds`
	}),
	addproto=((url)=>{
		if (!/^(?:f|ht)tps?\:\/\//.test(url))url = "https://" + url;
		return url;
	}),
	similar=((a,b)=>{
		var equivalency = 0;
		var minLength = (a.length > b.length) ? b.length : a.length;    
		var maxLength = (a.length < b.length) ? b.length : a.length;    
		for(var i=0;i<minLength;i++)if(a[i]==b[i])equivalency++;
		var weight = equivalency / maxLength;
		return (weight * 100);
	}),
	ready=(()=>{
		if(config.webserver.listenip=='0.0.0.0' || config.webserver.listenip=='127.0.0.1')config.webserver.listenip='localhost';
		var msg=`Listening on ${config.webserver.ssl ? 'https' : 'http'}://${config.webserver.listenip}:${workerData.port}${tt}`;
		threads.parentPort.postMessage({type:'log', id: threads.threadId, value: msg});
	}),
	btoa=(str,encoding)=>{
		return Buffer.from(str,'utf8').toString(( typeof encoding == 'undefined' ? 'base64' : encoding))
	},
	atob=(str,encoding)=>{
		return Buffer.from(str, ( typeof encoding == 'undefined' ? 'base64' : encoding)).toString('utf8')
	},
	proxyAgent = null;

if(config.proxy.vpn.enabled)proxyAgent = new socksProxyAgent('socks5://' + config.proxy.vpn.socks5);

global.sessions = {} // temp value!

global.workerData = {
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
			console.log(data);
			break
	}
});

String.prototype.exactRegex = function (flags, string = false){
	var reg = this.replace(/([\[|\]|\(|\)|\*|\\|\.|\+])/g,'\\$1');
	
	return (string ? reg : new RegExp(reg, flags) );
}

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(compression({
	level: 2
}));

http.globalAgent.maxSockets = Infinity;
https.globalAgent.maxSockets = Infinity;

if(!args || !args[0])ssl={key: fs.readFileSync('ssl/default.key','utf8'),cert:fs.readFileSync('ssl/default.crt','utf8')};
else switch(args[0].toLowerCase()){
	case'dev':
		tt=', DEV environment';
		ssl={key: fs.readFileSync('ssl/localhost.key','utf8'),cert:fs.readFileSync('ssl/localhost.crt','utf8')}
		break;
	default:
		ssl={key: fs.readFileSync('ssl/default.key','utf8'),cert:fs.readFileSync('ssl/default.crt','utf8')};
}
listen=config.webserver.listenip;
if(config.webserver.ssl==true)server=https.createServer(ssl,app).listen(workerData.port, config.webserver.listenip,ready);
else server=http.createServer(app).listen(workerData.port, config.webserver.listenip,ready);

require('./ws.js')(server);

app.use((req,res,next)=>{
	// hacky implementation of session stuff
	// this will add request.session ( a proxy thing acting as an object so it can see whats being added to push to the centeral script )
	
	req.fullURL = new URL('https://'+req.get('host')+req.originalUrl);
	
	var sid = req.cookies['connect.sid'],
		cookie = { maxAge: 900000, httpOnly: true, domain: req.fullURL.host.match(/\..{2,3}(?:\.?.{2,3}).*?$/gim), secure: true, sameSite: 'Lax' };
	
	if(sid == undefined || sid.length <= 7){
		while(true){
			sid=crypto.randomBytes(32).toString('hex');
			if(sessions[sid] != null)continue;
			break;
		}
	}
	
	res.cookie('connect.sid', sid , cookie);
	
	res.cookie('pm-server', os.hostname().substr(0,4).toLowerCase() , cookie);
	
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
	
	sessions[sid];
	
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
		fs.writeFileSync('urlData.json',JSON.stringify(urlData,null,'\t'),'utf-8');
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
	
	req.session.rpmEnabled = true
	
	req.session.rpm = url;
	
	res.redirect('/ses/');
	
	url = null
});

app.use(async (req,res,next)=>{
	if(req.query.ws != undefined)return next(); // noo websocket script did not handle 
	
	if(req.query.pmURL == null && (req.fullURL.pathname == '/' || req.fullURL.pathname.match(/^\/pm-cgi.*/) || req.fullURL.pathname == '/favicon.ico'))return next()
	else if(req.fullURL.pathname == '/sesUrl')return res.sendFile(path.join(__dirname + '/public/session.html'))
	else if(req.fullURL.pathname == '/clrSes'){
		req.session.expires = Date.now(); // set it so this session expires quicklyy
		return res.send(msgPage.replace('%TITLE%','Session data cleared').replace('%REASON%', 'All was done with success' ));
	}
	
	var data = {
			contentType: null,
			sendData: null,
			response: null,
			fetch_headers: {},
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
				}, 100);
			},
		},
		url;
	
	if(req.fullURL.pathname=='/https://discordapp.com/api/v6/auth/login')return res.status(400).contentType('application/json; charset=utf-8').send(JSON.stringify({ email: 'Use the QR code scanner or token login' }));
	
	var tooManyOrigins=new RegExp(`${req.fullURL.origin.replace(/\//g,'\\/').replace(/\./gi,'\\.')}\/`,'gi');
	if(req.url.substr(1).match(tooManyOrigins))return res.redirect(307,req.url.replace(tooManyOrigins,''));
	
	var tooManyOrigins=new RegExp(`//${req.fullURL.host.replace(/\\./g,'\\.')}`,'gi');
	if(req.url.substr(1).match(tooManyOrigins))return res.redirect(307,req.url.replace(tooManyOrigins,''));
	
	reloadURLs();
	
	var aliasMode=urlData.some(e=>req.url.match(new RegExp(`^/alias/${e.alias}`,'gi')));
	var shor='placeholder', newURL='placeholder', aliasSet='placeholder';
	
	if(req.fullURL.pathname.startsWith('/no_proxy/')){
		req.fullURL = new URL(req.fullURL.href.replace(/\/no_proxy\//gi, '/'));
		req.no_proxy = true;
	}
	
	if(req.query.pmURL != null && validURL(atob(req.query.pmURL)) ){
		url = new URL(atob(req.query.pmURL))
	}else if( aliasMode ){ // if a shortened url link matches in the url stuff
		
		urlData.forEach((e,i)=>{
			var regoink=new RegExp(`^\/alias\/${e.alias}`,'gi');
			if(req.fullURL.pathname.match(regoink)){
				shor=e.value; // set shortened to the value found within the url data stuff
				aliasSet = e.alias;
				newURL=req.url.replace(regoink,e.value);
				url=new URL(newURL);
				
			}
		});
		
	}else if(req.url.match(/^\/ses\//gi) ){
		
		if(!req.session.rpmEnabled)return genMsg(req, res, 403, 'You need a url session to access this page.');
			
		try {
			var tmp = new URL(req.session.rpm);
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
	
	
	if(req.query.pmURL == null && req.no_proxy != true && !aliasMode && req.session.rpmEnabled != true && poggerUrl != url.href)return res.redirect(307,'/'+url.href);
	
	// add the request body from a form or something if this was a post request
	
	if(req.method=='POST')data.fetch_options['body']=JSON.stringify(req.body);
	
	Object.entries(req.headers).forEach((e,i,a)=>{
		var name=e[0].toLowerCase();
		var value=e[1];
		
		// do not include cdn- or cloudflare- headers
		
		if(value.includes(url.host) || name.startsWith('Content-security-policy') || name.startsWith('x-') || name.startsWith('host') || name.startsWith('cf-') || name.startsWith('cdn-loop') )return;
		
		// add the header to the array
		
		data.fetch_headers[name] = value;
	});
	
	data.fetch_headers['referer'] = url.href
	
	var cookieStr='';
	Object.entries(req.cookies).forEach((e,i)=>{
		cookieStr+=`${e[0]}=${e[1]};`;
	});
	
	data.fetch_headers['cookie'] = cookieStr;
	data.fetch_options['headers'] = data.fetch_headers;
	
	data.response = await fetch(url, data.fetch_options).catch(err => {
		data.response = null
		
		if(req.msgShown)return;
		
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
	
	if(req.session.rpmEnabled != true && data.response != undefined && data.response.redirected == true){ // redirect has happened at least once
		return res.redirect(307, '/' + data.response.url);
	}else if(req.session.rpmEnabled == true && data.response.redirected == true){
		var tmp = new URL(data.response.url),
			tmp2 = '/ses';
		
		// need to set a new url in the session of the origin has changed from a redirect..
		
		if(tmp.origin != req.session.rpm){
			req.session.rpm = tmp.origin
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
	
	if(data.contentType.startsWith('text/html') && data.response.status == 200 && typeof req.query['pm-origin'] == 'undefined')req.session.ref=url.href;
	
	if(req.fullURL.href.match(/\.wasm$/gi))data.contentType = 'application/wasm'
	
	res.contentType(data.contentType);
	res.status(data.response.status);
	
	if(data.contentType.startsWith('application/x-shockwave-flash') || data.contentType.includes('font'))return res.send(data.sendData); // get straight to the font
	
	if(data.contentType.startsWith('image'))res.set('Cache-Control','max-age=31536000'); // big cache for images
	
	if(data.contentType.startsWith('text/') || data.contentType.startsWith('application/' && req.no_proxy != true) ){
		data.sendData = (()=>{ var output = ''; data.sendData.toString('utf8').split('\n').forEach(e=> output += e + '\n'); return output })(); // convert buffer to string
		
		var regUrlOri=req.fullURL.origin.replace('.','\\.').replace('/','\\/'), // safe way to have url origin in regex
			urlOri=url.origin.replace('.','\\.').replace('/','\\/'), // safe way to have url origin in regex
			regexFullOrigin = req.fullURL.origin.replace('.','\\.').replace('/','\\/'),
			urlDirectory = url.href.replace(/(.*?\/)[^\/]*?$/gi, '$1'); // https://google.com/bruh/ok.html => https://google.com/bruh/
		
		if(data.contentType.startsWith('text/css'))data.sendData = htmlMinify.minify('<style>' + data.sendData + '</style>', {minifyCSS: true, }).replace(/(?:^<style>|<\/style>$)/gi,''); // cool trick to get htmlMinify to minify a css file and have it display correctly
		
		data.sendData = await data.sendData
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
			
			return p1 + req.fullURL.origin + '/?pmURL=' + btoa(p2) + p3
		})
		;
		
		if(url.hostname != 'www.youtube.com')data.sendData = data.sendData // run this on not youtube links
		.replace(new RegExp(workerData.ip, 'gi'), randomIP());
		
		if(data.contentType.startsWith('text/html')){
			data.sendData = data.sendData
			
			// replace "//bing.com" => "https://bing.com"
			.replace(/(?<!base )((?:target|href|data-src|src|srcset|data|action)\s*?=\s*?(?:"|'))\/{2}/gi,'$1https://')
			
			// /websitelocalfilething => https://domain.tld/websitelocalfilething 
			.replace(/(?<!base )((?:target|href|data-src|src|srcset|data|action)\s*?=\s*?(?:"|'))((?!data:|javascript:)\/[\s\S]*?)((?:"|'))/gi,'$1' + url.origin + '$2$3')
			
			// ./img/bruh => https://domain.tld/directory/img/bruh
			.replace(/(?<!base )((?:target|href|data-src|src|srcset|data|action)\s*?=\s*?(?:"|'))\.\/([\s\S]*?)((?:"|'))/gi,'$1' + urlDirectory + '$2$3')
			
			// this does all the proxying magic!!! "https://otherdomain.tld => "https://localhost/https://otherdomain.tld
			.replace(new RegExp('("|\')(?=https?:\\/\\/)(?!' + regexFullOrigin + ')(.*?)\\1', 'gi'), '$1' + req.fullURL.origin + '/$2$1')
			.replace(/(xmlns(:[a-z]+)?=")\//gi, "$1")
			.replace(/(<!DOCTYPE[^>]+")\//i, "$1")
			.replace(new RegExp(`/(https://)${req.fullURL.host}/`,'gi'),'/$1')
			.replace(/ (integrity|nonce)[\s]*?=[\s]*?".*?" ?/gi,'') // integrity and nonce cant be used 
			.replace(/(\.integrity[\s]*?=[\s]*?)("|')([\s\S]*?)\2/gi, '$1null')
			// .replace(/('|")(wss:\/\/.*?)('|")/gi,'$1'+`wss://${req.fullURL.host}/?ws=`+"$2$3")
			.replace(/(?:document|window|location|window.location|document.location)(\.(?:href|host|hostname|pathname|port|protocol|hash|search))/gi,'pmURL$1')
			// pm url should be defined in a script somewhere
			// .replace(/<title.*?>.*?<\/ ?title>/gi,'<title>‮</title>')
			.replace(/("|').[^"']*\.ico(?:\?.*?)?("|')/gi,'$1/favicon.ico$2')
			.replace(/ ?onmousedown="return rwt\(this,.*?"/gi,'')
			.replace(/("|')_(?:blank|top|parent)\1/gi,'$1_self$1')
			.replace(/(<(?:iframe|object)\s*src=("|'))((?:(?!\?)[\s\S])*?)(?:\2)/gi,'$1$3?pm-origin='+btoa(url.host)+'$2') // this regex is for strings without the ? in it
			.replace(/(<(?:iframe|object)\s*src=("|'))((?:(?!&pm-origin=)[\s\S])*?)(?:\2)/gi,'$1$3&pm-origin='+btoa(url.host)+'$2') // this regex for the strings without the &pm-origin= inside of it
			.replace(new RegExp(`${regUrlOri}\/\.\/`,'gi'),`./`)
			.replace(new RegExp(`(?:${req.fullURL.origin}|${url.origin})/data:`,'gi'),'data:') // fix data urls last
			.replace(/(<script(?:.*?)>(?:(?!<\/script>)[\s\S])*<\/script>|<\/head>)/i,'<script  data="' + btoa(url.href) + '" src="/pm-cgi/preload.js"></script>$1')
			.replace(/history\.(pushstate|replacestate)/gi, 'emptyFunctionPreload')
			;
			
			if(!req.session.rpmEnabled){
				data.sendData = data.sendData
				.replace(/<\/head>/gi,'<script src="/pm-cgi/inject.js"></script></head>')
				;
			}
			
			if(!aliasMode && !req.session.rpmEnabled)data.sendData = data.sendData.replace(/<\/head>/gi,'<script src="/pm-cgi/windowURL.js"></script></head>')
			
			// replace reference to alias URL with alias
			else if(aliasMode)data.sendData = data.sendData.replace(new RegExp(`("|')(${ req.fullURL.origin })?\/${shor}(.*?)("|')`,'gi'),'$1/alias/'+aliasSet+'/$2$3')
			
			// replace like the session url is equal to https://discord.com/ and replace all links to the session url with the /ses/
			else if(req.session.rpmEnabled)data.sendData = data.sendData.replace(new RegExp(`("|')${ req.fullURL.origin }\\/${ req.session.rpm }(.*?)\\1`,'gi'),'$1/ses/$2$1');
			
			// on cloudflare checks, inform the user we cant proxy this page 
			if(data.sendData.includes('cf-browser-verification cf-im-under-attack'))data.sendData=data.sendData
			.replace(/<\/body>/gi,'  <script type="text/javascript" src="/pm-cgi/cloudflare.js"></script>\n</body>')
			.replace(/<\/head>/gi,'<link rel="stylesheet" href="/pm-cgi/cloudflare.css">\n</head>');
			
			if(config.workers && typeof req.query.debug == 'string' && req.query.debug == 'true')data.sendData=data.sendData.replace(/<\/body>/gi,`
<!-- [POWERMOUSE STATS]
Worker: ${threads.threadId}
Port: ${workerData.port}
Host: ${os.hostname()}
--></body>`);
			switch(url.host){
				case'discord.com':
					data.sendData=await data.sendData // hacky discord support
					.replace(`API_ENDPOINT: '//discord.com/api'`,`API_ENDPOINT: '/https://discordapp.com/api'`) // api for discord.com is odd but discordapp.com works
					//.replace(`REMOTE_AUTH_ENDPOINT: '//remote-auth-gateway.discord.gg'`,`REMOTE_AUTH_ENDPOINT: '//${req.fullURL.host}/?ws=wss://remote-auth-gateway.discord.gg'`)
					.replace(`WEBAPP_ENDPOINT: '//discord.com'`,`WEBAPP_ENDPOINT: '//${req.fullURL.host}/https://discord.com'`)
					.replace(`CDN_HOST: 'cdn.discordapp.com'`,`CDN_HOST: '${req.fullURL.host}/https://cdn.discordapp.com'`)
					.replace(`ASSET_ENDPOINT: '/https://discord.com'`,`ASSET_ENDPOINT: '${req.fullURL.origin}/https://discord.com'`)
					.replace(`WIDGET_ENDPOINT: '//discord.com/widget'`,`WIDGET_ENDPOINT: '//${req.fullURL.host}/https://discord.com/widget'`)
					.replace(`NETWORKING_ENDPOINT: '//router.discordapp.net'`,`NETWORKING_ENDPOINT: '//${req.fullURL.host}/https://router.discordapp.net'`)
					.replace(`MIGRATION_DESTINATION_ORIGIN: 'https://discord.com'`,`MIGRATION_DESTINATION_ORIGIN: '${req.fullURL.origin}/https://discord.com'`)
					.replace(`MIGRATION_SOURCE_ORIGIN: 'https://discordapp.com'`,`MIGRATION_SOURCE_ORIGIN: '${req.fullURL.origin}/https://discordapp.com'`)
					.replace(/<\/body>/gi,`<script type='text/javascript' src='/pm-cgi/discord.js'></script>`)
					;
					break;
				default:break;
			}
			try{ data.sendData=htmlMinify.minify(data.sendData, {minifyCSS: true, minifyJS: true});
			}catch(err){}
		}
	}
	
	if(config.cache.enabled && data.contentType.match(/^(video|audio|image|text\/css|application\/javascript)/gi) ){
		var folderPath = config.cache.dir + '/' + btoa(data.contentType).replace(/\//gi, '=-') + '/',
			cacheFile = folderPath + encodeURI(btoa(req.fullURL.href) ).replace(/\//gi, '=-');
		
		if(cacheFile.length <= 150){
			if(!fs.existsSync(folderPath) ){ // if the mime doesnt exist in the cache dir make it
				fs.mkdirSync(folderPath);
			}
			// 10000000 BYTES => 0.01 GB
			if(Buffer.byteLength(data.sendData) <= 10000000)fs.writeFileSync(cacheFile, data.sendData);
		}
	}
	
	res.send(data.sendData);
	
	return data.clearVariables();
});

app.use('/', express.static(path.join(__dirname, 'public')));