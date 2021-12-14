import time

from Case_rbm.iso_http_check_MIME_allow import index

from common import baseinfo

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameInside
windows_sip = baseinfo.windows_sip
front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid
http_server = baseinfo.http_server_ip
http_server_port = baseinfo.http_server_port
http_proxy_port = baseinfo.http_proxy_port
check1_uri = index.check1_uri
application_uri = index.application_uri
audio_uri = index.audio_uri
image_uri = index.image_uri
text_uri = index.text_uri
video_uri = index.video_uri

addhttp_front = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": front_ifname,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_server_port,
                "SeLabel": {},
                "Module": "http",
                "File": "off",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

addhttp_back = {
    "AddCustomAppPolicy": {
        "MethodName": "AddCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": back_ifname,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_server_port,
                "SeLabel": {},
                "Module": "http",
                "File": "off",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

delhttp_front = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": front_ifname,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "src",
            "Cards": front_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_server_port,
                "Module": "http",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

delhttp_back = {
    "DelCustomAppPolicy": {
        "MethodName": "DelCustomAppPolicy",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Ifname": back_ifname,
            "Dip": http_server,
            "Sip": windows_sip,
            "Domain": "dest",
            "Cards": back_cardid,
            "Applist": [{
                "Sport": "1-65535",
                "Appid": 20,
                "L3protocol": "ipv4",
                "Dport": http_server_port,
                "Module": "http",
                "Lport": http_proxy_port,
                "L4protocol": "tcp"}]
        }]}
}

httpcheck1 = {
    'SetHttpCheck': {
        "MethodName": "SetHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "mime",
            "DataCheck": [{"Action": 0,
                           "Data": check1_uri}
                          ]}]}
}
httpcheck2 = {
    'SetHttpCheck': {
        "MethodName": "SetHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "mime",
            "DataCheck": [{"Action": 0,
                           "Data": f"{application_uri};{audio_uri};{image_uri};{text_uri};{video_uri}"}
                          ]}]}
}
httpcheck3 = {
    'SetHttpCheck': {
        "MethodName": "SetHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": [{
            "Type": "mime",
            "DataCheck": [{"Action": 0,
                           "Data": "evy;fif;spl;hta;acx;hqx;doc;dot;*;bin;class;dms;exe;lha;lzh;oda;axs;pdf;prf;p10;crl;ai;eps;ps;rtf;setpay;setreg;xla;xlc;xlm;xls;xlt;xlw;msg;sst;cat;stl;pot;pps;ppt;mpp;wcm;wdb;wks;wps;hlp;bcpio;cdf;application/x-compress;z;cpio;csh;dcr;dir;dxr;dvi;gtar;gz;hdf;ins;isp;iii;js;latex;mdb;crd;clp;dll;m13;m14;mvb;wmf;mny;pub;scd;trm;wri;cdf;nc;pma;pmc;pml;pmr;pmw;p12;pfx;p7b;spc;p7r;p7c;p7m;p7s;sh;shar;swf;sit;sv4cpio;sv4crc;tar;tcl;tex;texi;texinfo;roff;t;tr;man;me;ms;ustar;src;cer;crt;der;pko;zip;au;snd;mid;rmi;mps;aif;aifc;aiff;m3u;ra;ram;wav;bmp;cod;gif;ief;jpe;jpeg;jpg;jfif;svg;tif;tiff;ras;cmx;ico;pnm;pbm;pgm;ppm;rgb;xbm;xpm;xwd;mht;mhtml;mws;css;323;htm;html;stm;uls;bas;c;h;txt;rtx;sct;tsv;htt;htc;etx;vcf;mp2;mpa;mpe;mpeg;mpg;mpv2;mov;qt;lsf;lsx;asf;asr;asx;avi;movie;flr;vrml;wrl;wrz;xaf;xof"}
                          ]}]}
}

delhttpcheck = {
    'DropHttpCheck': {
        "MethodName": "DropHttpCheck",
        "MessageTime": datatime,
        "Sender": "Centre0",
        "Content": []}
}
