# coding:utf-8
from common import baseinfo

url = baseinfo.http_proxy_url
proxy_ip = baseinfo.gwClientIp
proxy_port = baseinfo.http_proxy_port

# http相关参数设置
# post的下载只能是放在uri的后缀curl http://10.10.88.9:2286/1.pdf -v，且只能是get请求
file_name = "test."
uri = "doc"
base_uri = url + "/" + file_name + uri
action = "Allow"
"""
用例一：单个白名单

"Action":  "Allow",
"Method":  ["GET"],
"MIME":  ["text/plain"]
"""

check1_uri = "text/plain"
case1_uri = url + "/" + file_name + check1_uri

"""
用例二：多个白名单

"Action":  "Allow",
"Method":  ["GET"],
"MIME":  ["text/plain", "image/gif"]
"""

# application_uri = "js"
# audio_uri = "mps"
# image_uri = "gif"
# text_uri = "tsv"
# video_uri = "avi"
check2_uri = ["text/plain", "image/gif"]
case2_uri1 = url + "/" + file_name + check2_uri[0]
case2_uri2 = url + "/" + file_name + check2_uri[1]
# case2_uri3 = url + "/" + file_name + check2_uri[2]
# case2_uri4 = url + "/" + file_name + check2_uri[3]
# case2_uri5 = url + "/" + file_name + check2_uri[4]

"""
用例三：所有类型都设置为白名单

"Action":  "Allow",
"Method":  ["GET"],
"MIME":  ["evy", "fif", "spl", "hta", "acx", "hqx", "doc", "dot", "*", "bin", "class", "dms", "exe", "lha", "lzh",
 "oda", "axs", "pdf", "prf", "p10", "crl", "ai", "eps", "ps", "rtf", "setpay", "setreg", "xla", "xlc", "xlm", "xls",
  "xlt", "xlw", "msg", "sst", "cat", "stl", "pot", "pps", "ppt", "mpp", "wcm", "wdb", "wks", "wps", "hlp", "bcpio",
   "cdf", "application/x-compress", "z", "cpio", "csh", "dcr", "dir", "dxr", "dvi", "gtar", "gz", "hdf", "ins", "isp",
    "iii", "js", "latex", "mdb", "crd", "clp", "dll", "m13", "m14", "mvb", "wmf", "mny", "pub", "scd", "trm", "wri",
     "cdf", "nc", "pma", "pmc", "pml", "pmr", "pmw", "p12", "pfx", "p7b", "spc", "p7r", "p7c", "p7m", "p7s", "sh",
      "shar", "swf", "sit", "sv4cpio", "sv4crc", "tar", "tcl", "tex", "texi", "texinfo", "roff", "t", "tr", "man", 
      "me", "ms", "ustar", "src", "cer", "crt", "der", "pko", "zip", "au", "snd", "mid", "rmi", "mps", "aif", "aifc", 
      "aiff", "m3u", "ra", "ram", "wav", "bmp", "cod", "gif", "ief", "jpe", "jpeg", "jpg", "jfif", "svg", "tif", 
      "tiff", "ras", "cmx", "ico", "pnm", "pbm", "pgm", "ppm", "rgb", "xbm", "xpm", "xwd", "mht", "mhtml", "mws", 
      "css", "323", "htm", "html", "stm", "uls", "bas", "c", "h", "txt", "rtx", "sct", "tsv", "htt", "htc", "etx",
       "vcf", "mp2", "mpa", "mpe", "mpeg", "mpg", "mpv2", "mov", "qt", "lsf", "lsx", "asf", "asr", "asx", "avi", 
       "movie", "flr", "vrml", "wrl", "wrz", "xaf", "xof"]
"""
MIME_all = "evy;fif;spl;hta;acx;hqx;doc;dot;*;bin;class;dms;exe;lha;lzh;oda;axs;pdf;prf;p10;crl;ai;eps;ps;rtf;" \
       "setpay;setreg;xla;xlc;xlm;xls;xlt;xlw;msg;sst;cat;stl;pot;pps;ppt;mpp;wcm;wdb;wks;wps;hlp;bcpio;cdf;" \
       "application/x-compress;z;cpio;csh;dcr;dir;dxr;dvi;gtar;gz;hdf;ins;isp;iii;js;latex;mdb;crd;clp;dll;m13;" \
       "m14;mvb;wmf;mny;pub;scd;trm;wri;cdf;nc;pma;pmc;pml;pmr;pmw;p12;pfx;p7b;spc;p7r;p7c;p7m;p7s;sh;shar;swf;" \
       "sit;sv4cpio;sv4crc;tar;tcl;tex;texi;texinfo;roff;t;tr;man;me;ms;ustar;src;cer;crt;der;pko;zip;au;snd;" \
       "mid;rmi;mps;aif;aifc;aiff;m3u;ra;ram;wav;bmp;cod;gif;ief;jpe;jpeg;jpg;jfif;svg;tif;tiff;ras;cmx;ico;" \
       "pnm;pbm;pgm;ppm;rgb;xbm;xpm;xwd;mht;mhtml;mws;css;323;htm;html;stm;uls;bas;c;h;txt;rtx;sct;tsv;htt;" \
       "htc;etx;vcf;mp2;mpa;mpe;mpeg;mpg;mpv2;mov;qt;lsf;lsx;asf;asr;asx;avi;movie;flr;vrml;wrl;wrz;xaf;xof"

