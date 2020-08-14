var fancyButtons = eval(atob('WwoJCVsnUmVkZGl0Jywnb2xkLnJlZGRpdC5jb20nLCdvcmFuZ2UnXSwKCQlbJ0dvb2dsZScsJ3d3dy5nb29nbGUuY29tJywnZ3JlZW4nXSwKCQlbJ1lvdVR1YmUnLCd3d3cueW91dHViZS5jb20nLCdyZWQnXSwKCQlbJ0Rpc2NvcmQnLCd3d3cuZGlzY29yZC5jb20vbG9naW4nLCdibHVlJ10sCgld')),
	url_bar = document.querySelector('.url'),
	url_fill = document.querySelector('.url_fill'),
	activeElement = prevActiveEle = document.body,
	buttons_container = document.querySelector('.button_container'),
	addproto = (url)=>{
		if (!/^(?:f|ht)tps?\:\/\//.test(url))url = "https://" + url;
		return url;
	},
	getDifference = (begin,finish)=>{
		var ud=new Date(finish-begin);
		var s=Math.round(ud.getSeconds());
		var m=Math.round(ud.getMinutes());
		var h=Math.round(ud.getUTCHours());
		return `${h} hours, ${m} minutes, ${s} seconds`
	},
	getTimeStr = (ud)=>{
		if(typeof ud != 'Object')ud = new Date(Math.floor(ud));
		var s=Math.round(ud.getSeconds());
		var m=Math.round(ud.getMinutes());
		var h=Math.round(ud.getUTCHours());
		return `${h} hours, ${m} minutes, ${s} seconds`
	};

fancyButtons.forEach(e=>{
	var button = document.createElement('div');
	buttons_container.appendChild(button); // apend to container
	
	button.setAttribute('class','ns btn-fancy bnt-'+e[2]);
	button.innerHTML = e[0] // set contents of button
	
	button.addEventListener('click', ()=>{ // dont use a hrefs becaus that will show up in the document
		location.href = '/prox?url='+e[1];
	});
});

window.addEventListener('load', async()=>{
	var stats = await window.fetch('stats').then(e => e.json()),
		ping_element = document.querySelector('#ping'),
		uptime_value = stats.uptime, uptime_init = Date.now(), // keep these static
		uptime_element = document.querySelector('#uptime'),
		memory_element = document.querySelector('#memory');
	
	// set this before the interval as the interval doesnt start instantly
	
	ping_element.innerHTML = Date.now() - stats.start_time + ' ms'
	uptime_element.innerHTML = getTimeStr(stats.uptime * 1000 + (Date.now() - uptime_init));
	memory_element.innerHTML = (stats.memory / 1e+9).toString().substr(0, 5) + ' GB in use'
	
	setInterval(async ()=>{
		stats = await window.fetch('stats').then(e => e.json());
		ping_element.innerHTML = Date.now() - stats.start_time + ' ms'
		memory_element.innerHTML = (stats.memory / 1e+9).toString().substr(0, 5) + ' GB in use'
	}, 1000);
	
	setInterval(()=>{
		uptime_element.innerHTML = getTimeStr(uptime_value * 1000 + (Date.now() - uptime_init));
	}, 100);
});

url_bar.addEventListener('blur', e=>{
	if(prevActiveEle.getAttribute('class') == 'form-text url')return; // ignore element with that class when blurred
	
	Array.from(url_fill.getElementsByClassName('auto-fill')).forEach(e=>{
		e.parentNode.removeChild(e); // clean up old suggestions
	});
});

document.addEventListener('click', e=>{ // set the previous and active element as for the url selectors
	prevActiveEle = activeElement
	activeElement = e.target
});

url_bar.addEventListener('keyup', async e=>{
	var input = url_bar.value,
		response = await fetch('/suggestions?input=' + encodeURIComponent(input)),
		response_json = await response.json(); // our data is in a order of likely match to not likely match
	
	Array.from(url_fill.getElementsByClassName('auto-fill')).forEach(e=>{
		e.parentNode.removeChild(e); // clean up old suggestions
	});
	response_json.forEach((e,i)=>{
		var suggestion = document.createElement('div'),
			tldRegexp = /(?:\.{1,4}|\..{1,4}|\..{1,4}\..{1,4})($|\/)/gi,
			url = input.replace(tldRegexp,'.' + e + '$1');
		url_fill.appendChild(suggestion);
		suggestion.setAttribute('class','auto-fill ns');
		suggestion.innerHTML=url;
		
		suggestion.addEventListener('click', e=>{
			url_bar.value = url;
			url_bar.focus();
			Array.from(url_fill.getElementsByClassName('auto-fill')).forEach(ve=>{
				ve.parentNode.removeChild(ve); // clean up old suggestions
			});
		});
	});
});