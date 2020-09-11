const fs = require('fs'),
	os = require('os'),
	path = require('path'),
	util = require('util'),
	stream = require('stream'),
	rl = require('serverline'),
	cluster = require('cluster'),
	fetch = require('node-fetch'),
	config = JSON.parse(fs.readFileSync('config.json','utf8'));

var cluster_stderr = new stream.Transform({ decodeStrings: false }),
	workers = {
		broadcast: data => workers.instances.forEach((worker, i)=>{
			if(!worker.exitCode)return;
			worker.send(data);
		}),
		instances: [],
		online: 0,
		count: 0, // this gets set later, the amount of instances to create
		sessions: {},
		data: {
			type: 'worker_data',
			useragents: fs.readFileSync('useragents.txt', 'utf8'),
			port: process.env.PORT || config.webserver.port,
		}
	},
	makeWorker = id =>{
		var worker = cluster.fork();
		
		workers.instances[id] = worker
		worker.send(workers.data);
		worker.process.stderr.pipe(cluster_stderr); // pipe errors
		
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
			cluster_stderr.eventNames().forEach(event_name =>{
				if(cluster_stderr.listeners(event_name).length >= 6)cluster_stderr.listeners(event_name).forEach((event, event_index)=>{
					if(event_index == id){
						cluster_stderr.off(event_name, event);
					}
				});
			});
			
			if(code){
				workers.instances[id] = null
				
				// remove from online array
				workers.online--
				
				makeWorker(id); // make a new worker in its place
			}
		});
	};

if(config.proxy.vpn.enabled)console.log('Using socks5 proxy: socks5://' + config.proxy.vpn.socks5);

if(process.env.REPL_OWNER != null)workers.data.port = null; // on repl.it

setInterval(()=>{
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

(async()=>{
	process.env.NODE_ENV = 'production'
	
	cluster.setupMaster({
		exec: 'server.js',
		args: ['--use', 'http', '--use', 'http'],
		stdio: ['ignore', process.stdout, 'pipe', 'ipc'],
	});
	
	// we need the IP address to filter out on websites such as whatsmyip.org and other things
	workers.data.ip = await fetch('https://api.ipify.org/').then(res => res.text()).catch(err => '127.0.0.1' )
	
	// amount was manually set
	if(config.workers.manual_amount.enabled)workers.count = config.workers.manual_amount.count
	// normal, use amount of cpu threads
	else if(config.workers.enabled)workers.count = os.cpus().length
	// workers disabled
	else workers.count = 1
	
	for(var i = 0; i < workers.count; i++)makeWorker(i);
})();

rl.init();
rl.setPrompt('> ');
rl.on('line', (line)=>{
	var args = line.split(' '),
		mts = args.slice(1).join(' ');
	
	switch(args[0]){
		case'run': // debugging
			try{
				console.log(util.format(eval(mts)));
			}catch(err){
				console.log(util.format(err))
			}
			
			break
		case'reload':
			cluster_stderr.eventNames().forEach(event_name =>{ // remove listeners from error logging
				cluster_stderr.removeAllListeners(event_name);
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
		case'stop':
		case'exit':
			
			process.exit(0);
			
			break
		default:
			if(!args[0])return;
			
			console.log(path.basename(__filename) + ' ' + args[0] + ': command not found');
			
			break
	}
});

rl.on('SIGINT', rl => process.exit(0)); // ctrl+c quick exit

cluster_stderr._transform = (chunk, encoding, done)=>{
	var data = chunk.toString(),
		timestamp = new Date();
	
	fs.appendFileSync('./error.log', timestamp + '\n' + data);
	console.log(timestamp.toUTCString() + ' : encountered error, check error.log\n' + data);
	
	done(null, data);
}