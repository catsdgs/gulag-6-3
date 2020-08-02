var methods=['href','src','data'],
	newTitle='‮',
	logging=false,
	log=(str=>{
		if(!logging)return; // dont log if logging is false
		// take string and add formatting to make js logs seperate from unintentional errors 
		console.info('%c[Powermouse]','color: #805a00;',str);
	});

if(location.pathname=='/https://discord.com/' || location.pathname=='/https://discord.com/new')location.href='/https://discord.com/login';

var properUrlRegex=new RegExp(`^(${location.origin}|\\/https?:\\/\\/|^\\.\\/|^[^\\/]*|javascript:|data:)`,'gi'); // either the location origin or a local /https:// that is proxied
	externalSiteRegex=new RegExp(`^(?!${location.origin})(\/\/[^\/]|https?:\/\/)`,'gi');

setInterval(()=>{ // run every 0.25 seconds
	var linkElements=document.getElementsByTagName('a'); // all A links with a href
	Array.from(linkElements).forEach((element,i)=>{
		if(element.getAttribute('href') == null)return; // if there is no redirect on the link then ignore this one, its probably a hover over element
		
		var href=element.getAttribute('href').replace(/^\/\/([^\/])/gi,'https://$1');
		
		if(href.match(properUrlRegex)[0] == ''){ // this is not a proxied url!
			var newHref=location.origin+'/'+pmURL.origin+href
			
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