const fs = require('fs'),
	os = require('os'),
	path = require('path'),
	util = require('util'),
	stream = require('stream'),
	rl = require('serverline'),
	cluster = require('cluster'),
	fetch = require('node-fetch'),
	config = JSON.parse(fs.readFileSync('config.json','utf8'));

var workers = {
		broadcast: (data)=>{
			workers.instances.forEach((e,i)=>{
				if(e == null)return;
				e.send(data);
			});
		},
		instances: [],
		online: 0,
		errors: 0, // set this to 0 every 2 seconds 
		count: 0, // this gets set later, the amount of instances to create
		sessions: {},
		data: {
			type: 'workerData',
			banned_ua: fs.readFileSync('banned_ua.txt', 'utf8'),
			port: process.env.PORT || config.webserver.port,
		}
	},
	cluster_stuff = new stream.Transform({ decodeStrings: false }),
	makeWorker = (i)=>{
		if(config.workers.max_errors < workers.errors )return console.log('Error count at ' + config.workers.max_errors + ', refusing to create more workers..');
		
		cluster.setupMaster({
			exec: 'server.js',
			args: ['--use', (config.ssl == true ? 'http' : 'https --use http') ],
			silent: true,
		});
		
		var worker = cluster.fork();
		
		workers.instances[i] = worker
		
		if(process.env.REPL_OWNER != null)workers.data.port = null; // on repl.it
		
		worker.send(workers.data);
		
		worker.process.stdout.pipe(process.stdout);
		
		var stream_thing = worker.process.stderr.pipe(cluster_stuff);
		
		worker.on('message', (data)=>{
			switch(data.type){
				case'log':
					console.log(`Worker PID: ${worker.process.pid}: ${data.value}`)
					
					break
				case'started': // webserver initated on server.js instance
					
					workers.online++
					
					if(workers.online == workers.count){ // all workers active
						console.log(workers.online + '/' + workers.count + ' workers started, ' + data.msg); // listening on https://localhost:7080
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
		
		worker.once('exit', code => { // exit will only be called once
			cluster_stuff.eventNames().forEach(event_name =>{
				if(cluster_stuff.listeners(event_name).length >= 6)cluster_stuff.listeners(event_name).forEach((event, event_index)=>{
					if(event_index == i){
						cluster_stuff.off(event_name, event);
					}
				});
			});
			
			if(code != 0 && code != null){
				workers.errors++
				
				workers.instances[i] = null
				
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

setInterval(async ()=>{
	var v8_memory = await new Promise((resolve, reject)=>{
			var v8_memory = done = 0;
			
			workers.instances.forEach(worker=>{
				if(worker == null || !worker.isConnected())return;
				
				var callback = (data)=>{
						if(data.type = 'memoryUsage' && data.memoryUsage != undefined)v8_memory += data.memoryUsage.heapTotal
						done++
						
						if(done == workers.instances.length)resolve(v8_memory);
						
						worker.off('message', callback);
					}
				
				worker.send({type: 'memoryUsage'});
				
				worker.on('message', callback);
			});
		});
	
	workers.broadcast({ type: 'v8_memory', value: v8_memory });
	
}, 1000);

require('./url-manager.js');

(async()=>{
	// we need the IP address to filter out on websites such as whatsmyip.org and other things
	
	workers.data.ip = await fetch('https://api.ipify.org/').then(res => res.text()).catch((err)=> ipv = '127.0.0.1' )
	workers.data.tlds = /./g, tldList=[]
	
	var tldsv = await fetch('https://publicsuffix.org/list/effective_tld_names.dat').then(res => res.text()).catch((err)=> tldsv = '.com\n.org\n.net' );
	
	tldsv.split('\n').forEach((e,i,a)=>{
		if(!e.match(/(?:\*|\/\/|\s|\.)/gi) && e.length>=1){
			tldList.push(e);
			workers.data.tlds += e.replace('.','\\.') + '|'
		}
	});
	workers.data.tldRegex = new RegExp(`\\.(?:${workers.data.tlds.substr(0,workers.data.tlds.length-1)})$`,'gi');
	
	if(config.workers.manual_amount.enabled){ // amount was manually set
		workers.count = config.workers.manual_amount.count
	}else if(config.workers.enabled){ // normal, use amount of cpu threads
		workers.count = os.cpus().length
	}else workers.count = 1
	
	for(var i = 0; i < workers.count; i++)makeWorker(i);
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
			
			cluster_stuff.eventNames().forEach(event_name =>{ // remove listeners
				cluster_stuff.removeAllListeners(event_name);
			});
			 
			Object.keys(require.cache).forEach((key)=>{
				delete require.cache[key];
			});  
			
			workers.online = 0
			
			workers.instances.forEach( (worker, index)=>{
				if(worker != null && worker.isConnected())worker.kill('SIGTERM');
				
				worker = null
				
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

cluster_stuff._transform = function(chunk, encoding, done) {
	var data = chunk.toString();
	
	fs.appendFileSync('./error.log', data);
	console.log('Encountered error, check error.log\n' + data);
	
	return done(null, data);
}