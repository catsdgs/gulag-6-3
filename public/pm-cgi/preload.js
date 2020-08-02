var emptyFunctionPreload = ()=>{},
	pmURL = new URL(atob(document.currentScript.getAttribute('data'))),
	_windowfetch = window.fetch,
	_xmlopen = XMLHttpRequest.prototype.open,
	_websocket = WebSocket,
	_websockets = [],
	_replaceState = history.replaceState,
	_pushState = history.pushState,
	_image = Image,
	_createElement = document.createElement,
	proxifyURL = (url)=>{
		if(typeof url != 'string')return null;
		
		var pmDirectory = pmURL.href.replace(/(.*?\/)[^\/]*?$/gi, '$1'); // https://google.com/bruh/ok.html => https://google.com/bruh/
		
		// //ads.google.com => https://localhost/https://google.com
		
		url = url.replace(/(^\/{2}|^.{3,}:\/.{3,}:\/\/)/gi, 'https://');
		
		//   /bruh => /https://pmurl-domain.tld/bruh
		
		url = url.replace(/^\/(?!.{3,}:\/\/)\/?/gi, pmURL.origin + '/'); 
		
		/* bruh => /https://pmurl-domain.tld/bruh
		// notice the lack of a / at the start
		*/
		
		if(!url.match(/.{3,}:\/\//gi))url = pmDirectory + url
		
		/* url sometimes ends up as like https://localhost:7080/DASH_360.mp4 when it should NOT include the origin url inside of the
		// base64 crap done below below so it should work when replacing it with the pmURL's origin
		*/
		
		url = url.replace(new RegExp('^' + location.origin.replace(/\//g, '\\/').replace(/\./g, '\\.') , 'gi'), pmURL.origin);
		
		// url should be formed nicely so just like base64ify it
		
		url = location.origin + '/?pmURL=' + btoa(url);
		
		return url
	};

class ImageSpoof {
	constructor (){
		var args = arguments,
			img = new _image(args);
		
		img.addEventListener('loadstart', ()=>{
			var vsrc = img.src
			img.src = ''
			
			if(!vsrc.startsWith(location.origin))img.src = proxifyURL(vsrc);
		});
		
		return img
	}
}

class WebSocketSpoof {
	constructor (){
		var args = arguments,
			url = new URL(arguments[0]);
		
		if(url.host != location.host)url = new URL(`wss://${location.host}/?ws=${btoa(url.href)}`)
		
		var created_websocket = new _websocket(url.href);
		
		_websockets.push(created_websocket)
		
		return created_websocket;
	}
}

WebSocket = WebSocketSpoof
Image = ImageSpoof

document.createElement = function(){
	var args = arguments,
		element_type = args[0],
		element = _createElement.apply(this, args);
	
	setTimeout(()=>{
		switch(element_type){
			case'img':
				
				element.addEventListener('loadstart', ()=>{
					var vsrc = element.src
					element.src = ''
					
					if(!vsrc.startsWith(location.origin))element.src = proxifyURL(vsrc);
				});
				
				break
			case'a':
				element.addEventListener('mouseover', ()=>{
					var href = element.getAttribute('href'),
						newHref = href;
					
					// if href is like #asd or ?as
					
					if(href == null || href.match(/^[#?]/gi) )return;
					
					// /blog/bruh -> https://google.com/blog/bruh
					
					if(href.match(/^\/(?!\/)/gi))href = pmURL.origin + href
					
					// url isnt proxied
					
					if(!href.startsWith(location.origin))href = location.origin + '/' + href
					
					if(href != newHref)element.setAttribute('href', newHref); // change the attribute if theres any actual difference
				});
				
				break
			case'script':
				var src = element.getAttribute('src');
				
				element.setAttribute('src', proxifyURL(src) ); // change the attribute if theres any actual difference
				
				break
		}
	},2000);
	
	return element;
}

history.pushState = function(){
	var args = arguments,
		state = args[0],
		title = args[1],
		url = args[2];
	
	if(url.match(/^\/(?!\/)/gi))url = location.origin + '/' + pmURL.origin + url; // url starts with /
	
	return _pushState.apply(this, args);
}

history.pushState = function(){
	var args = arguments,
		state = args[0],
		title = args[1],
		url = args[2];
	
	// url starts with /
	
	if(url.match(/^\/(?!\/)/gi))url = location.origin + '/' + pmURL.origin + url;
	
	args[0] = state
	args[1] = title
	args[2] = url
	
	return _pushState.apply(this, args);
}

history.replaceState = function(){
	var args = arguments,
		state = args[0],
		title = args[1],
		url = args[2],
		regex_pm_origin;
	
	_pushState.apply(this, args);
	
	if(url.match(/^\/(?!\/|https:\/\/)/gi))url = location.origin + '/' + pmURL.origin + url; // url starts with /
	
	args[0] = state
	args[1] = title
	args[2] = url
	
	setTimeout(()=> _pushState.apply(this, args), 500);
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

window.Element = new Proxy(window.Element, {
	set: (obj, prop, value) => {
		console.log('SET:', obj, prop, value);
		
		obj[prop] = value;
		
		return true;
	}
});
var _setAttribute = window.Element.prototype.setAttribute

window.Element.prototype.setAttribute = function(){
	var args = arguments,
		target_class = args[0],
		target_value = args[1];
	
	
	
	switch(target_class){
		/*case'src':
			
			if(!target_value.startsWith(location.origin))target_value = proxifyURL(target_value);
			
			break
		
		case'href':
			if(target_value == null || target_value.match(/^[#?]/gi) )return;
			
			// /blog/bruh -> https://google.com/blog/bruh
			
			if(target_value.match(/^\/(?!\/)/gi))target_value = pmURL.origin + target_value
			
			// url isnt proxied
			
			if(!target_value.startsWith(location.origin))target_value = location.origin + '/' + target_value
			
			break
		
		*/
		
		case'data-src': // funky google thing!
			
			if(!target_value.startsWith(location.origin))target_value = proxifyURL(target_value);
			
			return this.style['background-image'] = 'url("' + target_value + '")'
			
			break
		default:
			break
	}
	
	// set these back again since they are not in sync
	
	args[0] = target_class
	args[1] = target_value
	
	_setAttribute.apply(this, args);
}