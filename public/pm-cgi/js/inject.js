var methods=['href','src','data'],
	newTitle='‮',
	logging=false,
	log = function(){
		if(!logging)return;
		console.info('%c[Powermouse]','color: #805a00;', ...arguments);
	};

var properUrlRegex=new RegExp(`^(${location.origin}|\\/https?:\\/\\/|^\\.\\/|^[^\\/]*|javascript:|data:)`,'gi'); // either the location origin or a local /https:// that is proxied
	externalSiteRegex=new RegExp(`^(?!${location.origin})(\/\/[^\/]|https?:\/\/)`,'gi');

setInterval(()=>{
	var iframe_elements = Array.from(document.querySelectorAll('iframe'));
	
	iframe_elements.forEach((element, element_index)=>{
		var src = element.getAttribute('src');
		
		if(src != null && src.match(/^(?!javascript:|data:|about:).*/gi)){ // not data: or javascript: or about:
			var new_src = src;
			
			if(new_src.match(/^\/(?!https?:\/\/).*/gi)){ // value starts with / and not anythin else
				new_src = pm_url.origin + new_src
			}
			
			if(!new_src.startsWith(location.origin))new_src = location.origin + '/' + new_src
			
			// check if new src is different before setting attribute to prevent a refresh or additional loading
			
			if(src != new_src)element.setAttribute('src', new_src);
		}
	});
}, 250);

/*
setInterval(()=>{ // run every 0.25 seconds
	var linkElements=document.getElementsByTagName('a'); // all A links with a href
	Array.from(linkElements).forEach((element,i)=>{
		if(element.getAttribute('href') == null)return; // if there is no redirect on the link then ignore this one, its probably a hover over element
		
		var href=element.getAttribute('href').replace(/^\/\/([^\/])/gi,'https://$1');
		
		if(href.match(properUrlRegex)[0] == ''){ // this is not a proxied url!
			var newHref=location.origin+'/'+pm_url.origin+href
			
			element.setAttribute('href',newHref);
		}else if( href.match(externalSiteRegex) != null ){ // external link
			var newHref=location.origin+'/'+href;
			
			element.setAttribute('href',newHref);
		}
	});
	var imageElements=document.getElementsByTagName('img'), // all images
		externalImgRegex=new RegExp(`^(?!${location.origin})(\/\/[^\/]|https?:\/\/)`,'gi');
	Array.from(imageElements).forEach((element,i)=>{
		if(element.getAttribute('src') == null)return;
		
		var src = element.getAttribute('src').replace(/^\/\/([^\/])/gi,'https://$1'),
			fixedSrc=false;
		
		if(src === null)return; // this image has no image????
		if(src.match(externalImgRegex)){
			fixedSrc=location.origin+'/'+src;
		}
		if(fixedSrc != false)element.setAttribute('src',fixedSrc);
	});
},500);
*/