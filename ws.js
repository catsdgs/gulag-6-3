const ws = require('ws'),
	fs=require('fs'),
	util=require('util');

var conns = 0,
	validURL = (url)=>{
		try{
			return new URL(url)
		}catch(err){
			return null
		}
	},
	base64regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/,
	wss = null;

module.exports = (server)=>{ // server is passed from the require('')(server) in module.exports
	wss = new ws.Server({
		server: server,
	});
	
	wss.on('connection',(cli, req)=>{
		var ID = String(++ conns).padStart(6, 0);
		
		req.query = (()=>{ var a = req.url.replace(/[\s\S]*?\?/i, '').replace(/\?/gi, '&').split('&'), b = {}; a.forEach(e => { var c = e.split('='); if(c[1] == null)b[c[0]] = null; else b[c[0]] = c[1] });return b })();
		
		if(req.query.ws == null) {
			cli.send('Missing URL Flag `ws`!');
			return cli.close(1008);
		}
		
		/*
		// non base64 version
		
		var wsURL = req.query.ws + (()=>{
			var a = req.query, b = []; // copy the array to not modify original
			delete a.ws;
			Object.entries(a).forEach((e,i)=>{
				b.push(e[0] + '=' + e[1])
			});
			return '?' + b.join('&')
		})();
		*/
		
		var wsURL = atob(req.query.ws);
		
		if(validURL(wsURL) == null) {
			cli.send('your url is garbage!!!');
			return cli.close(1008);
		}
		
		var svr = new ws(wsURL);
		
		svr.on('error',err=>{
			try{
				cli.close(1011); // SERVER ERROR
			}catch(err){}
		});
		
		cli.on('error',()=>{
			try{
				svr.close(1001); // CLOSE_GOING_AWAY
			}catch(err){}
		});
		
		svr.on('message',msg=>{
			try{
				cli.send(msg);
			}catch(err){}
		});
		
		cli.on('message',msg=>{
			try{
				svr.send(msg);
			}catch(err){}
		});
		svr.on('close',e=>{
			try{
				cli.close(e);
			}catch(err){}
		});
		cli.on('close',e=>{
			try{
				svr.close(e);
			}catch(err){}
		});
	});
}