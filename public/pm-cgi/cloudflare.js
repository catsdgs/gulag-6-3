var info=document.createElement('div'),
	dismiss=document.createElement('div');

document.body.appendChild(info);

info.innerHTML='Notice! Cloudflare under attack mode has been proven to not work while under a proxy!';
info.appendChild(dismiss);

info.style.opacity=1;

dismiss.innerHTML='&times;';
info.setAttribute('class','infoMsg');
dismiss.setAttribute('class','dismiss ns');

dismiss.addEventListener('click',()=>{
	info.style.opacity=0;
	setTimeout(()=>info.parentNode.removeChild(info),100);
});

//document.getElementById('challenge-form').submit();