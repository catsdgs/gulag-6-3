var getDifference=((begin,finish)=>{
		var ud=new Date(finish-begin);
		var s=Math.round(ud.getSeconds());
		var m=Math.round(ud.getMinutes());
		var h=Math.round(ud.getUTCHours());
		return `${h} hours, ${m} minutes, ${s} seconds`
	}),
	addproto=((url)=>{
		if (!/^(?:f|ht)tps?\:\/\//.test(url))url = "https://" + url;
		return url;
	}),
	form=document.getElementById('mainForm'),
	logMsg=document.getElementById('logMsg'),
	urlBar=document.getElementsByClassName('url')[0];

form.addEventListener('submit',(e)=>{
	urlBar.value=addproto(urlBar.value); // add protocol on the client first, server does this too
	try{
		new URL(urlBar.value);
	}catch(err){
		e.preventDefault();
		logMsg.innerHTML=err.message;
	}
});