// SWAMI KARUPPASWAMI THUNNAI

var domain_visited =  window.location.href;
const url =  document.createElement("a");
url.setAttribute("href", domain_visited);
var hostname = url.hostname;
console.log(hostname);
var xmlHttp = new XMLHttpRequest();
xmlHttp.open("GET", "http://127.0.0.1:5660/is_domain_blocked?host="+hostname, false); 
xmlHttp.setRequestHeader("Content-type", "application/json");
xmlHttp.setRequestHeader("Access-Control-Allow-Origin", "*");
xmlHttp.send();
console.log("Sent");
let is_blocked = JSON.parse(xmlHttp.responseText);
console.log(is_blocked);
if(is_blocked["message"] == true)
{
	window.location.href = "http://127.0.0.1:5660/blocked";
}
