var data = JSON.parse(decodeURI(atob(document.currentScript.getAttribute('data')))),
	pm_url = new Proxy(new URL(data.pm_url), {
		get: function(target, prop, receiver){
			var ret;
			
			if(prop == 'replace'){
				return function(){
					if(arguments[0] != null)return location.replace.apply(location, [proxify_url(arguments[0], false)]);
				}
			}else try {
				ret = Reflect.get(...arguments);
			}catch(err){
				ret = target[prop]
			}
			
			return ret
		},
		set: _=> true
	}),
	pm_log = function(){return console.log('%c[Powermouse]', 'color: #800080;', ...arguments)},
	proxify_url = (url, encode = true)=>{ // by default, encode the url
		if(typeof url != 'string')return url;
		
		if(url.match(/^(?=moz-|blob:|javascript:|data:|about:)/gi))return url; // data urls
		
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
		
		if(encode && url.length <= 1024)url = location.origin + '/?pm_url=' + btoa(url)
		else url = location.origin + '/' + url
		
		return url
	},
	state_proxify_url = url =>{
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

window.parent = {}

// anti-iframe for A specific domain
if(window.parent.location != window.location && pm_url.host == atob('ZGlzY29yZC5jb20='))window.parent.location = window.location;

[{
	url: '/pm-cgi/js/urlrewrite.js?' + data.urlrewrite_date,
	conditions: (!data.alias_mode && data.pm_session != true)
},{
	url: '/pm-cgi/js/inject.js?' + data.inject_date,
	conditions: (data.pm_session != true)
}].forEach(script=>{
	// if script already loaded or conditions are not met, return
	if(!script.conditions)return;
	
	pm_log('loading script ' + script.url);
	
	fetch(script.url, {}).then(res => res.text()).then(body => eval.call(window, body) && (()=>{
		pm_log('script ' + script.url + ', finished loading');
	})());
});

// request functions

window.fetch = new Proxy(window.fetch, {
	apply(target, thisArg, argArray){
		// proxify url
		if(argArray[0])argArray[0] = proxify_url(argArray[0], false);
		
		return target.apply(thisArg, argArray);
	}
});

XMLHttpRequest.prototype.open = new Proxy(XMLHttpRequest.prototype.open, {
	apply(target, thisArg, argArray){
		// proxify url
		if(!argArray[1].match(/^\/pm-cgi\//gi))argArray[1] = proxify_url(argArray[1], false)
		
		target.apply(thisArg, argArray);
	}
});

Navigator.prototype.sendBeacon = new Proxy(Navigator.prototype.sendBeacon, {
	apply(target, thisArg, argArray){
		if(argArray[0])argArray[0] = proxify_url(argArray[0], false);
		
		return target.apply(thisArg, argArray);
	}
});

window.open = new Proxy(window.open, {
	apply(target, thisArg, argArray){
		argArray[0] = proxify_url(argArray[0], false);
		
		target.apply(thisArg, argArray);
	}
});

window.postMessage = new Proxy(window.postMessage, {
	apply(target, thisArg, argArray){
		if(argArray[1] != undefined)argArray[1] = location.origin // only possible origin can be the current one
		
		return target.apply(thisArg, argArray);
	}
});

// DOM stuff

document.createElement = new Proxy(document.createElement, {
	apply(target, thisArg, argArray){
		var element_type = argArray[0],
			element = target.apply(thisArg, argArray);
		
		if(argArray[1] != 'override' && element_type != null && element_type != undefined)switch(element_type.toLowerCase()){
			case'img':
				
				element.addEventListener('loadstart', ()=>{
					var src = element.src
					
					if(src && !src.startsWith(location.origin))element.src = proxify_url(src);
				});
				
				break
			case'a':
				element.addEventListener('mouseover', ()=>{
					var href = element.getAttribute('href'),
						old_href = href;
					
					// if href is like #asd or ?as
					
					if(href == null || href.match(/^[#\?]/gi) )return;
					
					href = proxify_url(href, false); // proxify it without encoding 
					
					if(href != old_href)element.setAttribute('href', href); // change the attribute if theres any actual difference
				});
				
				break
			case'script':
				var src = element.getAttribute('src');
				
				if(src != null)element.setAttribute('src', proxify_url(src) );
				
				// remove integrity in scripts, cant support that
				setTimeout(()=>{ var integrity = element.getAttribute('integrity'); if(integrity != null)element.removeAttribute('integrity') }, 100);
				
				break
		}
		
		return element;
	}
});

Element.prototype.setAttribute = new Proxy(Element.prototype.setAttribute, {
	apply(target, thisArg, [target_class, target_value]){
		switch(target_class){
			case'src':
				
				if(target_value != null && target_value != undefined){
					if(!target_value.startsWith(location.origin))target_value = proxify_url(target_value);
				}
				
				break
			case'xlink:href':
			case'data-src': // funky google thing!
				
				if(!target_value.startsWith(location.origin))target_value = proxify_url(target_value);
				
				return thisArg.style['background-image'] = 'url("' + target_value + '")'
				
				break
		}
		
		target.apply(thisArg, [target_class, target_value]);
	}
});

Element.prototype.appendChild = new Proxy(Element.prototype.appendChild, {
	apply(target, thisArg, [node]){
		switch(node.nodeName.toLowerCase()){
			case 'iframe':
				if(!node.src && node.contentWindow){ // remove iframe function protection junk
					node.contentWindow.fetch = window.fetch;
				}
				
				var src = node.getAttribute('src');
				
				if(src && src != proxify_url(src, false))node.setAttribute('src', proxify_url(src, false));
				
				break
			case 'script':
				var src = node.getAttribute('src');
				
				if(src != null){
					if(proxify_url(src, false) != src)node.setAttribute('src', proxify_url(src, false) );
				}
				
				break
			case 'link':
				var href = node.getAttribute('href');
				
				if(href != null){
					if(proxify_url(href) != href)node.setAttribute('href', proxify_url(href) );
				}
				
				break
		}
		
		return target.apply(thisArg, [node]);
	}
});

Element.prototype.setAttribute = new Proxy(Element.prototype.setAttribute, {
	apply(target, thisArg, argArray){
		var value = argArray[1];
		
		if(argArray[1] != 'override' && value != null)switch(argArray[0].toLowerCase()){
			case 'href':
				value = proxify_url(value, false);
				break
			case 'src': if(!value.match(/favicon\.ico(\?.*?)?$/gi)){ // not favicon
				value = proxify_url(value, false);
			}	break
		}
		
		return target.apply(thisArg, argArray);
	}
});

window.Image = class extends Image {
	constructor(){
		var img = super(...arguments),
			load_start_callback = img =>{
				if(img.src != 'undefined' && typeof vsrc == 'string' && !img.src.startsWith(location.origin)){
					img.src = proxify_url(img.src);
					img.removeEventListener('loadstart', load_start_callback);
				}
			};
		
		img.addEventListener('loadstart', load_start_callback);
		
		if(img.parentNode)img = new Proxy(img, {
			get(target, prop, receiver){
				var ret;
				
				try { ret = Reflect.get(...arguments);
				}catch(err){ ret = target[prop] }
				
				return ret
			},
			set(obj, prop, value){
				if(arguments[1] == 'src' && arguments[2])arguments[2] = proxify_url(arguments[2]);
				
				arguments[0][arguments[1]] = arguments[2]
				
				// indicate success?
				return true
			}
		});
		
		return img
	}
}

// workers and websockets

window.WebSocket = class extends WebSocket {
	constructor(){
		var url = new URL(arguments[0]);
		
		if(url.host != location.host)url = new URL( (location.protocol == 'https:' ? 'wss' : 'ws') + '://' + location.host + '/?ws=' + btoa(url.href))
		
		return super(url.href);
	}
}

window.Worker = class extends Worker {
	constructor(){
		return super(proxify_url(arguments[0]), arguments[1])
	}
}

// history functions

history.pushState = new Proxy(history.pushState, {
	apply(target, thisArg, argArray){
		if(argArray[2])argArray[2] = state_proxify_url(argArray[2]);
		
		return target.apply(thisArg, argArray);
	}
});

history.replaceState = new Proxy(history.replaceState, {
	apply(target, thisArg, argArray){
		var ret = target.apply(thisArg, argArray);
		
		// replacestate as intended first, then replace again with new data
		
		argArray[2] = state_proxify_url(argArray[2]);
		setTimeout(()=>{ target.apply(thisArg, argArray) }, 1000);
		
		return ret;
	}
});

window.addEventListener('DOMContentLoaded', ()=>{
	Array.from(document.querySelectorAll('style[data-href]')).forEach(element=>{
		var g_href = element.getAttribute('data-href'); // weird google href?
		
		if(g_href != null){
			var new_stylesheet = document.createElement('link');
			
			element.parentNode.replaceChild(new_stylesheet, element);
			
			new_stylesheet.setAttribute('rel', 'stylesheet');
			
			new_stylesheet.setAttribute('href', g_href);
		}
	});
});