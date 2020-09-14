var data = JSON.parse(decodeURI(atob(document.currentScript.getAttribute('data'))));

globalThis.pm_url = new Proxy(new URL(data.pm_url), {
	get(target, prop, receiver){
		var ret;
		
		if(prop == 'replace'){
			return function(){
				if(arguments[0] != null)return location.replace.apply(location, [proxify_url(arguments[0], false)]);
			}
		}else try{
			ret = Reflect.get(...arguments);
		}catch(err){
			ret = target[prop]
		}
		
		return ret
	},
	set: _=> true
});

globalThis.proxify_url = (url, encode = true)=>{ // by default, encode the url
	if(typeof url != 'string')return url;
	
	if(url.match(/^(?=moz-|chrome|blob:|javascript:|data:|about:)/gi))return url; // data urls
	
	var pmDirectory = pm_url.href.replace(/(.*?\/)[^\/]*?$/gi, '$1'); // https://google.com/bruh/ok.html => https://google.com/bruh/
	
	// //ads.google.com => https://localhost/https://google.com
	
	url = url.replace(/(^\/{2}|^.{3,}:\/.{3,}:\/\/)/gi, 'https://');
	
	//   /bruh => /https://pm_url-domain.tld/bruh
	
	url = url.replace(/^\/(?!.{3,}:\/\/)\/?/gi, pm_url.origin + '/'); 
	
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
}

globalThis.state_proxify_url = url =>{
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
}

globalThis.rewrite_page = () => {
	var accurate_url = new URL(location.origin + '/' + pm_url.origin + location.href.substr(location.origin.length)),
		origin_check = location.origin + '/' + pm_url.origin,
		origin_check_alt = location.origin + '/' + pm_url.origin.replace(/^http(s?):\/(?!\/)/gi, 'http$1://');
	
	if(!window.page_redirecting && !location.toString().startsWith(origin_check) && !location.toString().startsWith(origin_check_alt))history.pushState({ page_id: 1, user_id: 5 }, '', accurate_url.href);
	
	document.querySelectorAll('*[data-href], *[data-src], *[x-link], *[src]').forEach(node => Array.from(node.attributes).forEach(attr => {
		switch(attr.name){
			case'src':
				// already modified?
				if(attr.value.startsWith(location.origin + '/' + pm_url.origin))return;
				
				node.setAttribute(attr.name, proxify_url(attr.value));
				
				break
			case'href':
				if(attr.value.startsWith(location.origin + '/' + pm_url.origin))return;
				
				node.setAttribute(attr.name, proxify_url(attr.value, false));
				
				break
			case'xlink:href':
			case'data-src': // funky google thing!
				if(!attr.value.startsWith(location.origin + '/' + pm_url.origin))node.setAttribute(attr.name, proxify_url(attr.value));
				
				return node.style['background-image'] = 'url(\'' + attr.value + '\')'
				
				break
			case'data-src': // stylesheet that is messed up
				
				var new_ss = document.createElement('link');
				
				node.parentNode.replaceChild(new_ss, node);
				new_ss.setAttribute('rel', 'stylesheet');
				new_ss.setAttribute('href', attr.value);
				
				break
			case'style':
				var old_val = attr.value,
					new_val = old_val.replace(/((?::\s*|\s)url\()("|')?(?=[^\+])([\s\S]*?)\2(\))/gi, (match, p1, p2, p3, p4, offset, string)=>{
						var part = p1,
							quote = (p2 == undefined ? '' : p2),
							toproxy_url = p3,
							end_part = p4;
						
						toproxy_url = proxify_url(toproxy_url)
						
						return part + quote + toproxy_url + quote + end_part
					});
				
				if(old_val != new_val)node.setAttribute(attr.name, new_val);
				
				break
		}
	}));
}

// anti-iframe for A specific domain
if(window.parent.location != window.location && pm_url.host == atob('ZGlzY29yZC5jb20='))window.parent.location = window.location;

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
		// proxify urls that are not part of pm-cgi
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
				/*element.addEventListener('mouseover', ()=>{
					var href = element.getAttribute('href'),
						old_href = href;
					
					// if href is like #asd or ?as
					
					if(href == null || href.match(/^[#\?]/gi) )return;
					
					href = proxify_url(href, false); // proxify it without encoding 
					
					if(href != old_href)element.setAttribute('href', href); // change the attribute if theres any actual difference
				});*/
				
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
		}
		
		target.apply(thisArg, [target_class, target_value]);
	}
});

Element.prototype.appendChild = new Proxy(Element.prototype.appendChild, {
	apply(target, thisArg, [node]){
		switch(node.nodeName.toLowerCase()){
			case 'iframe':
				if(!node.src && node.contentWindow)node.contentWindow.fetch = window.fetch;
				
				var src = node.getAttribute('src');
				
				if(src && src != proxify_url(src, false))node.setAttribute('src', proxify_url(src, false));
				
				break
			case 'script':
				var src = node.getAttribute('src');
				
				if(src != null){
					if(proxify_url(src, false) != src)node.setAttribute('src', proxify_url(src, false) );
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
			get: (target, prop, receiver) => Reflect.get(target, prop, receiver),
			set(obj, prop, value){
				if(prop == 'src' && value)value = proxify_url(value);
				
				return Reflect.set(obj, prop, value);
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

rewrite_page();
setInterval(rewrite_page, 250);

window.addEventListener('beforeunload', _ => window.page_redirecting = true );
window.addEventListener('onunload', _ => window.page_redirecting = false );