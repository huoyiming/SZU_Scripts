import random,requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from bs4 import BeautifulSoup
from base64 import b64encode
# 请在下方填写你的学号和密码
username=''
password=''

# 生成随机字符串
_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
def _rds(len):
    retStr = ''
    for i in range(len):
        retStr += random.choice(_chars)
    return retStr

# 加密
def _gas(data, key0, iv0):
    key0 = key0.strip()
    key = key0.encode('utf-8')
    iv = iv0.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return b64encode(encrypted_data).decode('utf-8')

def encryptAES(data,salt):
    if not salt:
        return data
    else:
        encrypted = _gas(_rds(64)+data, salt, _rds(16))
        return encrypted
    
session = requests.session()
headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,ja;q=0.7,en-US;q=0.6,en;q=0.5,zh-HK;q=0.4',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded',
    # 'Cookie': 'org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE=zh_CN; route=344d0012ba2e8536ed53d954a6c3aeb0; JSESSIONID_PERSON=IO29QYBq20_g_ubQJCkAAXPftZxjyfl4PZsGHPh-z9hfDmJP4zSv!-154982064; MOD_AUTH_CAS=MOD_AUTH_ST-29051-EMrchpvxNgoz77lZ2TjX1708277203781-WgEd-cas; JSESSIONID_auth=UXO9QZAhn0c5nB9a1ZHOpquUA6qXZYWKf2_7n5W_5vD7qIjYR-7R!-272030971',
    'DNT': '1',
    'Origin': 'https://authserver.szu.edu.cn',
    'Referer': 'https://authserver.szu.edu.cn/authserver/login',
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
html=session.get('https://authserver.szu.edu.cn/authserver/login',headers=headers)
html_doc=html.text
soup = BeautifulSoup(html_doc, 'html.parser')
salt=soup.find(id="pwdDefaultEncryptSalt")["value"]
data={
    'username':username,
    'password':encryptAES(password,salt),
    'lt':soup.find('input', {'name': 'lt'})["value"],
    'dllt': 'userNamePasswordLogin',
    'execution': soup.find('input', {'name': 'execution'})["value"],
    '_eventId': 'submit',
    'rmShown': soup.find('input', {'name': 'rmShown'})["value"]
}
cookies = html.cookies.get_dict()
cookies['org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE']='zh_CN'
# print(data)
loginreq=session.post('https://authserver.szu.edu.cn/authserver/login',data=data,headers=headers,cookies=cookies)
www1=session.get('https://www1.szu.edu.cn/board/infolist.asp',headers=headers)
www1.encoding='gbk'
print(www1.text)