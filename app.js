const fs = require('fs'),
	os = require('os'),
	util = require('util'),
	rl = require('serverline'),
	fetch = require('node-fetch'),
	cluster = require('cluster'),
	path = require('path'),
	config = JSON.parse(fs.readFileSync('config.json','utf8'));

var workers = {
		broadcast: ((data)=>{
			workers.instances.forEach((e,i)=>{
				e.send(data);
			});
		}),
		instances: [],
		online: 0,
		sessions: {},
		errors: 0, // set this to 0 every 2 seconds 
		worker_count: 0, // this gets set later
	},
	ip, tlds, tldsv, bad_useragents_regex = fs.readFileSync('bot_ua_regex.txt', 'utf8'),
	makeWorker = (i)=>{
		if(config.workers.max_errors < workers.errors )return console.log('Error count at ' + config.workers.max_errors + ', refusing to create more workers..');
		
		cluster.setupMaster({
			exec: 'server.js',
			args: ['--use', (config.ssl == true ? 'http' : 'https --use http') ],
			silent: false,
		});
		
		const index = i;
		
		var worker_port = process.env.PORT || config.webserver.port;
		
		if(process.env.REPL_OWNER != null)worker_port = null; // on repl.it
		
		var worker = cluster.fork();
		
		worker.send({ type: 'workerData', bad_useragents_regex: bad_useragents_regex, port: worker_port, ip: ip, tldRegex: tldRegex, tldList: tldList });
		
		workers.instances[index] = worker
		
		worker.on('listening', (address) => {
			// address: { addressType: 4, address: '127.0.0.1', port: 7080, fd: undefined }
			
		});
		
		worker.on('message', (data)=>{
			switch(data.type){
				case'log':
					console.log(`Worker PID: ${worker.process.pid}: ${data.value}`)
					
					break
				case'started': // webserver initated on server.js instance
					
					workers.online++
					
					if(workers.online == workers.worker_count){ // all workers active
						console.log(workers.online + '/' + workers.worker_count + ' workers started, ' + data.msg); // listening on https://localhost:7080
					}
					 
					break
				case'store_set':
					workers.sessions[data.sid] = data.session;
					
					workers.broadcast({ type: 'update_session', sessions: workers.sessions });
					
					break
				case'store_get':
					workers.sessions[data.sid].__lastAccess = Date.now();
					
					worker.postMessage({ to: 'store_get', session: workers.sessions[data.sid] })
					
					break
				case'store_del':
					delete workers.sessions[data.sid]
					
					break
			}
		});
		
		worker.on('exit', (code) => {
			if(code !=0 ){
				console.log('Worker stopped with exit code ' + code);
				
				workers.errors++
				
				workers.instances[index] = null
				
				// remove from online array
				workers.online--
				
				makeWorker(i); // make a new worker in its place
			}
		});
	};

if(config.proxy.vpn.enabled)console.log('Using socks5 proxy: socks5://' + config.proxy.vpn.socks5);

setInterval(()=>{
	workers.errors = 0
	
	Object.entries(workers.sessions).forEach((e,i)=>{
		var session=e[1];
		var key=e[0];
		
		var expires = session['__lastAccess'] + config.proxy.session_timeout, // the time this session should go away
			timeLeft = expires - Date.now(),
			expired = timeLeft <= 0;
		
		if(expired){
			delete workers.sessions[key]; // delete object thingo
			workers.broadcast({ type: 'update_session', sessions: workers.sessions }); // send updated worker sessions
		}
	});
}, 5000);

require('./url-manager.js');

(async()=>{
	// we need the IP address to filter out on websites such as whatsmyip.org and other things
	
	ip = await fetch('https://api.ipify.org/').then(res => res.text()).catch((err)=> ipv = '127.0.0.1' ),
	tlds = /./g, tldList=[],
	tldsv = await fetch('https://publicsuffix.org/list/effective_tld_names.dat').then(res => res.text()).catch((err)=> tldsv = '.com\n.org\n.net' );
	
	tldsv.split('\n').forEach((e,i,a)=>{
		if(!e.match(/(?:\*|\/\/|\s|\.)/gi) && e.length>=1){
			tldList.push(e);
			tlds += e.replace('.','\\.') + '|'
		}
	});
	tldRegex = new RegExp(`\\.(?:${tlds.substr(0,tlds.length-1)})$`,'gi');
	
	if(config.workers.manual_amount.enabled){ // amount was manually set
		workers.worker_count = config.workers.manual_amount.count
	}else if(config.workers.enabled){ // normal, use amount of cpu threads
		workers.worker_count = os.cpus().length
	}else workers.worker_count = 1
	
	for(var i = 0; i < workers.worker_count; i++)makeWorker(i);
})();

rl.init();
rl.setPrompt('> ');
rl.on('line', (line)=>{
	var args=line.split(' '),
		mts=line.substr(args[0].length+1,128);
	
	switch(args[0]){
		case'run': // debugging
			try{console.log(util.format(eval(mts)))}
			catch(err){console.log(util.format(err))};
			break
			
		case'reload':
			workers.errors = 0 // allow new ones to be created
			
			Object.keys(require.cache).forEach((key)=>{
				delete require.cache[key];
			});  
			
			workers.online = 0
			
			workers.instances.forEach( (worker, index)=>{
				if(worker != null)process.kill(worker.process.pid);
				
				makeWorker(index);
			});
			
			break
			
		case'stop':case'exit':
			process.exit(0);
			break
			
		default:
			if(!args[0])return; // if slap enter key
			console.log(path.basename(__filename) + ' ' + args[0] + ': command not found');
			break
	}
});
rl.on('SIGINT',(rl)=>process.exit(0)); // ctrl+c quick exit