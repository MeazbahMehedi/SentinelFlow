/* Apply saved/system appearance before the stylesheet paints. No inline scripts. */
(function(){
'use strict';
const root=document.documentElement;
let saved=null;try{saved=localStorage.getItem('sentinelflow-theme');}catch(_){}
const system=matchMedia('(prefers-color-scheme: light)');
function apply(theme){root.dataset.theme=theme;root.style.colorScheme=theme;document.querySelectorAll('[data-theme-toggle]').forEach(button=>{button.setAttribute('aria-label','Switch to '+(theme==='dark'?'light':'dark')+' mode');button.setAttribute('title','Switch to '+(theme==='dark'?'light':'dark')+' mode');button.setAttribute('aria-pressed',String(theme==='light'));const use=button.querySelector('use');if(use)use.setAttribute('href','/static/img/icons.svg#'+(theme==='light'?'moon':'sun'));});window.dispatchEvent(new Event('themechange'));}
apply(saved==='light'||saved==='dark'?saved:(system.matches?'light':'dark'));
document.addEventListener('DOMContentLoaded',()=>{apply(root.dataset.theme);document.querySelectorAll('[data-theme-toggle]').forEach(button=>button.addEventListener('click',()=>{const theme=root.dataset.theme==='dark'?'light':'dark';try{localStorage.setItem('sentinelflow-theme',theme);}catch(_){}saved=theme;apply(theme);}));});
system.addEventListener('change',event=>{if(!saved)apply(event.matches?'light':'dark');});
})();
