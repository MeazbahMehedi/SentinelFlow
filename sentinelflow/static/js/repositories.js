'use strict';
(function(){
const accounts=[...document.querySelectorAll('[data-github-account]')],data=new Map();let loading=false;
const search=document.querySelector('#repo-search'),language=document.querySelector('#repo-language'),kind=document.querySelector('#repo-kind'),button=document.querySelector('#repo-refresh');
const make=(tag,cls,text)=>{const element=document.createElement(tag);if(cls)element.className=cls;if(text!==undefined)element.textContent=text;return element;};
function safeDate(value){const d=new Date(value);return isNaN(d)?'Date unavailable':d.toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'});}

const states={live:'Live refresh',cached:'Cached',stale:'Offline cache',unavailable:'Unavailable'};
function renderProfile(section,profile){
 const p=profile||{state:'unavailable',message:'Public profile is temporarily unavailable.'};
 const login=section.dataset.githubAccount;
 section.querySelector('[data-profile-name]').textContent=p.name||login;
 section.querySelector('[data-profile-bio]').textContent=p.bio||(p.state==='unavailable'?'Open the GitHub profile above or refresh after reconnecting.':'No public bio on GitHub yet.');
 const details=section.querySelector('[data-profile-details]');details.replaceChildren();
 if(p.location)details.append(make('span','',p.location));
 if(p.company)details.append(make('span','',p.company));
 if(p.joined_at)details.append(make('span','','Joined '+safeDate(p.joined_at)));
 if(p.website){const link=make('a','text-link','Website ↗');link.href=p.website;link.target='_blank';link.rel='noopener noreferrer';details.append(link);}
 const stats=section.querySelector('[data-profile-stats]');stats.replaceChildren();
 for(const [key,label] of [['public_repos','Public repos'],['followers','Followers'],['following','Following']]){
  if(Number.isInteger(p[key])){const stat=make('div','');stat.append(make('strong','',p[key].toLocaleString()),make('span','',label));stats.append(stat);}
 }
 const status=section.querySelector('[data-profile-status]');status.textContent='Profile: '+(states[p.state]||'Unavailable')+(p.fetched_at?' · Fetched '+new Date(p.fetched_at*1000).toLocaleString():'')+'. '+(p.message||'');
 const avatar=section.querySelector('[data-github-avatar]'),fallback=section.querySelector('[data-avatar-fallback]');
 avatar.onload=()=>{avatar.hidden=false;fallback.hidden=true;};
 avatar.onerror=()=>{avatar.hidden=true;fallback.hidden=false;};
 if(p.avatar_url){const url=new URL(p.avatar_url);url.searchParams.set('s','128');url.searchParams.set('sf_refresh',String(Math.floor((p.fetched_at||0)/300)));if(avatar.getAttribute('src')!==url.href)avatar.src=url.href;}
 else {avatar.removeAttribute('src');avatar.hidden=true;fallback.hidden=false;}
}

function render(){
 const query=search.value.trim().toLowerCase();let matching=0,total=0;
 for(const section of accounts){const info=data.get(section.dataset.githubAccount);if(!info)continue;const list=section.querySelector('[data-repo-list]');list.replaceChildren();total+=info.repos.length;
 const repos=info.repos.filter(r=>(!query||(r.name+' '+r.description+' '+r.topics.join(' ')).toLowerCase().includes(query))&&(!language.value||r.language===language.value)&&(!kind.value||(kind.value==='fork'?r.fork:!r.fork)));
 matching+=repos.length;
 if(!repos.length){const empty=make('div','empty');empty.append(make('strong','',info.state==='unavailable'?'Projects are temporarily unavailable':info.repos.length?'No matching repositories':'No public repositories yet'),make('span','',info.state==='unavailable'?'Use the profile link above or try again after the connection recovers.':info.repos.length?'Try another keyword or filter.':'New public projects appear after the next successful refresh.'));list.append(empty);continue;}
 for(const repo of repos){const card=make('article','repository-card'),heading=make('div','repository-title'),link=make('a','',repo.name);link.href=repo.url;link.target='_blank';link.rel='noopener noreferrer';heading.append(link,make('span','pill',repo.archived?'ARCHIVED':repo.fork?'FORK':'PUBLIC'));card.append(heading,make('p','',repo.description||'No description provided.'));
 if(repo.topics.length){const tags=make('div','repo-topics');repo.topics.forEach(t=>tags.append(make('span','',t)));card.append(tags);}
 const meta=make('div','repository-meta'),lang=make('span','repo-language'),dot=make('i','language-dot');dot.dataset.language=repo.language;lang.append(dot,document.createTextNode(repo.language));meta.append(lang,make('span','','★ '+repo.stars),make('span','','⑂ '+repo.forks),make('span','repo-updated','Updated '+safeDate(repo.updated_at)));card.append(meta);list.append(card);}
 }
 document.querySelector('#repo-total').textContent=matching.toLocaleString()+' matching / '+total.toLocaleString()+' loaded';
}
function renderStatus(section,info){const state=section.querySelector('[data-repo-state]');state.textContent=states[info.state]||'Unavailable';state.className='badge '+(info.state==='live'?'finished':info.state==='cached'?'investigating':'paused');section.querySelector('[data-repo-count]').textContent=info.repos.length+' public repos'+(info.truncated?' · latest 1,000':'');section.querySelector('[data-repo-updated]').textContent=info.fetched_at?'Fetched '+new Date(info.fetched_at*1000).toLocaleTimeString():'No successful fetch yet';section.querySelector('[data-repo-message]').textContent=info.message;}
async function load(){if(loading)return;loading=true;button.disabled=true;try{await Promise.all(accounts.map(async section=>{const login=section.dataset.githubAccount;let info;try{const response=await fetch('/api/github/'+encodeURIComponent(login));if(!response.ok)throw new Error('Request failed');info=await response.json();}catch(_){info={login,profile:data.get(login)?.profile?{...data.get(login).profile,state:'stale',message:'Unable to reconnect to the workspace.'}:null,repos:data.get(login)?.repos||[],state:data.has(login)?'stale':'unavailable',fetched_at:data.get(login)?.fetched_at||null,message:'Unable to connect to the workspace. Refresh after reconnecting.'};}data.set(login,info);renderStatus(section,info);renderProfile(section,info.profile);}));const selected=language.value;const languages=[...new Set([...data.values()].flatMap(d=>d.repos.map(r=>r.language)))].sort();language.replaceChildren(new Option('All languages',''));languages.forEach(l=>language.append(new Option(l,l)));language.value=languages.includes(selected)?selected:'';render();}finally{loading=false;button.disabled=false;}}
search.addEventListener('input',render);language.addEventListener('change',render);kind.addEventListener('change',render);button.addEventListener('click',load);load();setInterval(()=>{if(!document.hidden)load();},300000);
})();
