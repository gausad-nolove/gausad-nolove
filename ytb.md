#!name=Youtube Premium 
#!desc=Unlock Gấuytb 1001 

 
/****************************** 
📌 Tác Giả：unlockytb  
📌 Cập Nhật：3728392      
******************************/ 

 
[Rule]   
AND,((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP)),REJECT   
AND,((DOMAIN,youtubei.googleapis.com), (PROTOCOL,UDP)),REJECT   

[URL Rewrite]     
(^https?:\/\/[\w-]+\.googlevideo\.com\/(?!dclk_video_ads).+?)&ctier=L(&.+?),ctier,(.+) $1$2$3 302   
^https?:\/\/[\w-]+\.googlevideo\.com\/(?!(dclk_video_ads|videoplayback\?)).+&oad _ reject-200   
^https?:\/\/(www|s)\.youtube\.com\/api\/stats\/ads _ reject-200   
^https?:\/\/(www|s)\.youtube\.com\/(pagead|ptracking) _ reject-200   
^https?:\/\/s\.youtube\.com\/api\/stats\/qoe\?adcontext _ reject-200   

[Script]   
youtube.request = type=http-request,pattern=^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/(browse|next|player|reel\/reel_watch_sequence|get_watch),requires-body=1,max-size=-1,binary-body-mode=1,engine=script-engine,script-path= https://raw.githubusercontent.com/gausad-nolove/Shadowrocket/refs/heads/main/ytn.js   
youtube.response = type=http-response,pattern=^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/(browse|next|player|search|reel\/reel_watch_sequence|guide|account\/get_setting|get_watch),requires-body=1,max-size=-1,binary-body-mode=1,engine=script-engine,script-path= https://raw.githubusercontent.com/gausad-nolove/Shadowrocket/refs/heads/main/README.js,argument="{"lyricLang":"off", "captionLang":"off","blockUpload":false,"blockImmersive":false,"debug":false}"   

[MITM]   
hostname = %APPEND% -redirector*.googlevideo.com,*.googlevideo.com,www.youtube.com,s.youtube.com,youtubei.googleapis.com   
