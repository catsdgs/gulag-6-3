var fancyButtons = eval(atob('WwoJCVsnUmVkZGl0Jywnb2xkLnJlZGRpdC5jb20nLCdvcmFuZ2UnXSwKCQlbJ0dvb2dsZScsJ3d3dy5nb29nbGUuY29tJywnZ3JlZW4nXSwKCQlbJ1lvdVR1YmUnLCd3d3cueW91dHViZS5jb20nLCdyZWQnXSwKCQlbJ0Rpc2NvcmQnLCd3d3cuZGlzY29yZC5jb20vbG9naW4nLCdibHVlJ10sCgld')),
	_cihash = ((r)=>{for(var a,o=[],c=0;c<256;c++){a=c;for(var f=0;f<8;f++)a=1&a?3988292384^a>>>1:a>>>1;o[c]=a}for(var n=-1,t=0;t<r.length;t++)n=n>>>8^o[255&(n^r.charCodeAt(t))];return(-1^n)>>>0})(navigator.userAgent),
	charInsert = str =>{
		var words = str.split(' '),	
			output = '';
		
		words.forEach((word, word_index) =>{
			var chars = word.split('');
			
			chars.forEach((chr, chr_index)=>{
				var entity = '&#' + chr.charCodeAt();
				output += '<span style="white-space: nowrap">'
				
				if(chr_index == 0 || chr_index == word.length )output += entity;
				else output += '&#8203;<span style="display:none;font-size:0px;">&#8203;...' + _cihash + '</span>' + entity + '&#8203;';
				
				output += '</span>'
			});
			
			if(word_index != words.length - 1)output += ' '
		});
		
		return output
	},
	url_bar = document.querySelector('.input-url'),
	url_fill = document.querySelector('.tld-autofill'),
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
	button.innerHTML = charInsert(e[0]) // set contents of button
	
	button.addEventListener('click', ()=>{ // dont use a hrefs becaus that will show up in the document
		location.href = '/prox?url='+e[1];
	});
});

window.addEventListener('load', async()=>{
	var stats = await window.fetch('stats').then(e => e.json()),
		uptime_value = stats.uptime, uptime_init = Date.now(), // keep these static
		uptime_element = document.querySelector('#uptime');
	
	// set this before the interval as the interval doesnt start instantly
	
	uptime_element.innerHTML = getTimeStr(stats.uptime * 1000 + (Date.now() - uptime_init));
	
	setInterval(async ()=>{
		stats = await window.fetch('stats').then(e => e.json());
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
	if(url_bar.value.length <= 0)return Array.from(url_fill.getElementsByClassName('auto-fill')).forEach(e=>{
		e.parentNode.removeChild(e); // clean up old suggestions
	});
	
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
		suggestion.innerHTML = charInsert(url);
		
		suggestion.addEventListener('click', e=>{
			url_bar.value = url;
			url_bar.focus();
			Array.from(url_fill.getElementsByClassName('auto-fill')).forEach(ve=>{
				ve.parentNode.removeChild(ve); // clean up old suggestions
			});
		});
	});
});