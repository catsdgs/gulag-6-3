var data = JSON.parse(decodeURI(atob(document.currentScript.getAttribute('data'))));

var emptyFunctionPreload = ()=>{},
	pm_url = new URL(data.pm_url),
	pm_log = function(){
		return console.log('%c[Powermouse]', 'color: #800080;', ...arguments)
	},
	_windowfetch = window.fetch,
	_xmlopen = XMLHttpRequest.prototype.open,
	_worker = Worker
	_websocket = WebSocket,
	_websockets = [],
	_replaceState = history.replaceState,
	_pushState = history.pushState,
	_postMessage = postMessage,
	_image = Image,
	_createElement = document.createElement,
	_setAttribute = window.Element.prototype.setAttribute,
	_eps = Element.prototype.setAttribute,
	_epa =  Element.prototype.appendChild,
	_encoded_urls = true,
	proxifyURL = (url)=>{
		if(typeof url != 'string')return url;
		
		if(url.match(/^(?=blob:|javascript:|data:|about:)/gi))return url; // data urls
		
		var pmDirectory = pm_url.href.replace(/(.*?\/)[^\/]*?$/gi, '$1'); // https://google.com/bruh/ok.html => https://google.com/bruh/
		
		// //ads.google.com => https://localhost/https://google.com
		
		url = url.replace(/(^\/{2}|^.{3,}:\/.{3,}:\/\/)/gi, 'https://');
		
		//   /bruh => /https://pm_url-domain.tld/bruh
		
		url = url.replace(/^\/(?!.{3,}:\/\/)\/?/gi, pm_url.origin + '/'); 
		
		if(url == null)url = '';
		
		/* bruh => /https://pm_url-domain.tld/bruh
		// notice the lack of a / at the start
		*/
		
		if(!url.match(/.{3,}:\/\//gi))url = pmDirectory + url
		
		/* url sometimes ends up as like https://localhost:7080/DASH_360.mp4 when it should NOT include the origin url inside of the
		// base64 crap done below below so it should work when replacing it with the pm_url's origin
		*/
		
		url = url.replace(new RegExp('^' + location.origin.replace(/\//g, '\\/').replace(/\./g, '\\.') , 'gi'), pm_url.origin);
		
		// url should be formed nicely so just like base64ify it
		
		if(_encoded_urls && url.length <= 1024)url = location.origin + '/?pm_url=' + btoa(url)
		else url = location.origin + '/' + url
		
		return url
	},
	state_proxifyURL = (url)=>{
		var url = url
		
		if(url == undefined)return url
		
		if(data.alias_mode){
			// url starts with /, replace with alias stuff
			if(url.match(/^\/(?!\/|https?:\/\/|alias\/)/gi))url = location.origin + '/' + data.alias_url + '/' + url
			
			url = url.replace(pm_url.origin, '/' + data.alias_url + '/')
		}else if(data.pm_session == true){
			// url starts with /, replace with /ses/
			if(url.match(/^\/(?!\/|https?:\/\/)/gi))url = location.origin + '/ses/' + url
			
			url = url.replace(pm_url.origin, '/ses/')
			
		}else{
			// url starts with /
			if(url.match(/^\/(?!\/|https?:\/\/)/gi))url = location.origin + '/' + pm_url.origin + url
		}
		
		return url
	};

(()=>{ // variable scope is needed for require to not mess with rest of code
	var scripts = [
		{
			url: location.origin + '/pm-cgi/windowURL.js?' + data.windowURL_date,
			conditions: (!data.alias_mode && data.pm_session != true)
		},
		{
			url: location.origin + '/pm-cgi/inject.js?' + data.inject_date,
			conditions: (data.pm_session != true)
		},
	]
	
	scripts.forEach(script=>{
		if(script.conditions == true){ // if conditions to load script are actually met
			pm_log('loading script ' + script.url);
			var tmp = _createElement.apply(document, ['script']);
			document.head.appendChild(tmp);
			_setAttribute.apply(tmp, ['src', script.url] );
			tmp.addEventListener('load', ()=>{
				pm_log('script ' + script.url + ', finished loading');
			});
		}
	});
})();

postMessage = function(){
	var args = arguments;
	
	if(args[1] != undefined)args[1] = location.origin // only possible origin can be the current one
	
	_postMessage.apply(this, args);
}

Element.prototype.appendChild = function(){
	var args = arguments,
		element = args[0];
	
	switch(element.nodeName.toLowerCase()){
		case 'iframe':
			var src = element.getAttribute('src');
			
			if(src != null && src.match(/^(?!blob:|javascript:|data:|about:).*/gi)){ // not data: or javascript: or about:
				var new_src = src;
				
				if(new_src.match(/^\/(?!https?:\/\/).*/gi)){ // value starts with / and not anythin else
					new_src = pm_url.origin + '/' + new_src
				}
				
				if(!new_src.startsWith(location.origin))new_src = location.origin + '/' + new_src
				
				element.setAttribute('src', new_src);
			}
			
			break
		case 'script':
			var src = element.getAttribute('src');
			
			if(src != null){
				if(!src.startsWith(location.origin) && src.match(/^(?!blob:|javascript:|data:|about:).*/gi))element.setAttribute('src', proxifyURL(src) );
			}
			
			break
		case 'link':
			var href = element.getAttribute('href');
			
			if(href != null){
				if(!href.startsWith(location.origin) && href.match(/^(?!blob:|javascript:|data:|about:).*/gi) )element.setAttribute('href', proxifyURL(href) );
			}
			
			break
	}
	
	args[0] = element
	
	return _epa.apply(this, args);
}

Element.prototype.setAttribute = function(){
	var args = arguments,
		target = args[0],
		value = args[1];
	
	if(value != null)switch(target.toLowerCase()){
		case 'href':
			if(!value.match(/^(?:blob:|javascript:|data:|about:):/gi)){ // dont do data url stuff
				if(value.match(/^\/(?!https?:\/\/).*/gi)){ // value starts with / and not anythin else
					value = pm_url.origin + value
				}
				
				if(value != '' && !value.startsWith(location.origin)){ // proxify url
					value = location.origin + '/' + value
				}
			}
			
			break
		case 'src': if(!value.match(/favicon\.ico(\?.*?)?$/gi)){ // not favicon
			
			if(value.match(/^\/(?!https?:\/\/).*/gi)){ // value starts with / and not anythin else
				value = pm_url.origin + value
			}
			
			if(!value.startsWith(location.origin)){ // proxify url
				value = location.origin + '/' + value
			}
			
		}	break
	}
	
	args[0] = target
	args[1] = value
	
	return _eps.apply(this, args);
}

class ImageSpoof {
	constructor (){
		var args = arguments,
			img = new _image(args),
			load_start_callback = (img)=>{
				
				
				if(img.src != 'undefined' && typeof vsrc == 'string' && !img.src.startsWith(location.origin)){
					img.src = proxifyURL(img.src);
					img.removeEventListener('loadstart', load_start_callback);
				}
			};
		
		img.addEventListener('loadstart', load_start_callback);
		
		if(img.parentNode != null)img = new Proxy(img, {
			get: function(target, prop, receiver){
				var ret;
				
				try {
					ret = Reflect.get(...arguments);
				}catch(err){
					ret = target[prop]
				}
				
				return ret
			},
			set: function(obj, prop, value){
				var args = arguments
				
				if(args[1] == 'src' && args[2] != undefined){
					args[2] = proxifyURL(args[2]);
				}
				
				args[0][args[1]] = args[2]
				
				return true
			}
		});
		
		return img
	}
}

class WebSocketSpoof {
	constructor (){
		var args = arguments,
			url = new URL(arguments[0]);
		
		if(url.host != location.host)url = new URL( (location.protocol == 'https:' ? 'wss' : 'ws') + '://' + location.host + '/?ws=' + btoa(url.href))
		
		var created_websocket = new _websocket(url.href);
		
		_websockets.push(created_websocket)
		
		return created_websocket;
	}
}

class WorkerSpoof {
	constructor(){
		var args = arguments,
			aURL = args[0],
			options = args[1],
			output = null;
		
		output = new _worker(proxifyURL(aURL), options);
		
		return output
	}
}

Worker = WorkerSpoof
WebSocket = WebSocketSpoof
Image = ImageSpoof

document.createElement = function(){
	var args = arguments,
		element_type = args[0],
		element = _createElement.apply(this, args);
	
	switch(element_type.toLowerCase()){
		case'img':
			
			element.addEventListener('loadstart', ()=>{
				var vsrc = element.src
				
				if(vsrc != undefined && !vsrc.startsWith(location.origin))element.src = proxifyURL(vsrc);
			});
			
			break
		case'a':
			element.addEventListener('mouseover', ()=>{
				var href = element.getAttribute('href'),
					old_href = href;
				
				// if href is like #asd or ?as
				
				if(href == null || href.match(/^[#\?]/gi) )return;
				
				// /blog/bruh -> https://google.com/blog/bruh
				
				if(href.match(/^\/(?!\/)/gi))href = pm_url.origin + href
				
				// url isnt proxied
				
				if(!href.startsWith(location.origin))href = location.origin + '/' + href
				
				if(href != old_href)element.setAttribute('href', href); // change the attribute if theres any actual difference
			});
			
			break
		case'script':
			var src = element.getAttribute('src');
			
			element.setAttribute('src', proxifyURL(src) );
			
			break
	}
	
	return element;
}

history.pushState = function(){
	var args = arguments,
		state = args[0],
		title = args[1],
		url = args[2];
	
	url = state_proxifyURL(url);
	
	return _pushState.apply(this, args);
}

history.replaceState = function(){
	var args = arguments,
		state = args[0],
		title = args[1],
		url = args[2],
		regex_pm_origin,
		returnthing = _replaceState.apply(this, args);
	
	url = state_proxifyURL(url);
	
	args[0] = state
	args[1] = title
	args[2] = url
	
	setTimeout(()=>{ _replaceState.apply(this, args) }, 1000);
	
	return returnthing;
}

window.fetch = (url, options)=>{
	url = proxifyURL(url);
	
	return _windowfetch(url, options);
}

XMLHttpRequest.prototype.open = function() {
	var args = arguments,
		url = arguments[1];
	
	url = proxifyURL(url);
	
	args[1] = url
	
	_xmlopen.apply(this, args);
}

window.Element.prototype.setAttribute = function(){
	var args = arguments,
		target_class = args[0],
		target_value = args[1];
	
	switch(target_class){
		case'src':
			
			if(target_value != null && target_value != undefined){
				if(!target_value.startsWith(location.origin))target_value = proxifyURL(target_value);
			}
			
			break
		case'xlink:href':
		case'data-src': // funky google thing!
			
			if(!target_value.startsWith(location.origin))target_value = proxifyURL(target_value);
			
			return this.style['background-image'] = 'url("' + target_value + '")'
			
			break
	}
	
	_setAttribute.apply(this, [target_class, target_value]);
}

_Navigator_sendBeacon = Navigator.prototype.sendBeacon // set before modifying

Navigator.prototype.sendBeacon = function(url, data){
	var url = url,
		data = data;
	
	return _Navigator_sendBeacon.apply(this, [proxifyURL(url), data]);
}

window.addEventListener('DOMContentLoaded', ()=>{
	Array.from(document.querySelectorAll('style[data-href]')).forEach(element =>{
		var g_href = element.getAttribute('data-href'); // weird google href?
		
		if(g_href != null){
			var new_stylesheet = document.createElement('link');
			
			element.parentNode.replaceChild(new_stylesheet, element);
			
			new_stylesheet.setAttribute('rel', 'stylesheet');
			
			new_stylesheet.setAttribute('href', g_href);
		}
	});
});