var redirecting=false;

window.addEventListener('beforeunload',e=>redirecting=true);
window.addEventListener('onunload',e=>redirecting=false);

setInterval(()=>{
	/*
	var newURL=new URL(location.origin+'/'+pm_url.origin+location.href.substr(location.origin.length));
	if(!redirecting && !location.toString().startsWith(location.origin+'/'+pm_url.origin) ){
		history.pushState({ 'page_id': 1, 'user_id': 5 }, newTitle, newURL.href);
	}
	*/
},500);