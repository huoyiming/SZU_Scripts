import random,requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from bs4 import BeautifulSoup
from base64 import b64encode
# 请在下方填写你的学号和密码
username=''
password=''

authserver_url = 'https://authserver.szu.edu.cn'
# 通过指定的字符集生成特定长度随机字符串，用以AES加密
aeschars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
def randomString(len):
    retStr = ''
    for i in range(len):
        retStr += random.choice(aeschars)
    return retStr

# AES加密函数
def getAesString(data, key0, iv0):
    key0 = key0.strip()
    key = key0.encode('utf-8')
    iv = iv0.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return b64encode(encrypted_data).decode('utf-8')
# 主要函数，调用上述两个函数加密密码
def encryptAES(data,salt):
    if not salt:
        return data
    else:
        encrypted = getAesString(randomString(64)+data, salt, randomString(16))
        return encrypted
    
session = requests.session()
headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,ja;q=0.7,en-US;q=0.6,en;q=0.5,zh-HK;q=0.4',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded',
    'DNT': '1',
    'Origin': authserver_url,
    'Referer': f'{authserver_url}/authserver/login',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}
# 获取原始网页，以得到某些需要的参数
html=session.get(f'{authserver_url}/authserver/login',headers=headers)
html_doc=html.text
soup = BeautifulSoup(html_doc, 'lxml')
# 从网页中提取加密密码的盐值
salt=soup.find(id="pwdEncryptSalt")["value"]
# 登录请求的参数
data={
    'username':username,
    'password':encryptAES(password,salt),
    'rememberMe':'on',
    'lt':soup.find('input', {'name': 'lt'})["value"],
    'dllt': soup.find('input', {'name': 'dllt'})["value"],
    'captcha':'',
    'cllt':'userNameLogin',
    'execution': soup.find('input', {'name': 'execution'})["value"],
    '_eventId': 'submit',
    'rmShown': soup.find('input', {'name': 'rmShown'})["value"]
}
# 加入特定cookies
cookies = html.cookies.get_dict()
cookies['org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE']='zh_CN'
# 发送登陆请求
loginreq=session.post(f'{authserver_url}/authserver/login',data=data,headers=headers,cookies=cookies)
