import random,requests,json,time,datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from bs4 import BeautifulSoup
from base64 import b64encode
# 学号和密码
username=''
password=''

# 推送参数
pushtoken=''# push token
pushtopic=''# pushplus中一对多推送的群组id

authserver_url = 'https://authserver-443.webvpn.szu.edu.cn'
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
try:
    week_list = ["星期一","星期二","星期三","星期四","星期五","星期六","星期日"]
    def time2day(time):
        try:
            time=time.split(' ')[0].split('-')
            return week_list[datetime.date(int(time[0]), int(time[1]), int(time[2])).weekday()]
        except:
            return '转换失败'

    # 通过指定的字符集生成特定长度随机字符串，用以AES加密
    _chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    def _rds(len):
        retStr = ''
        for i in range(len):
            retStr += random.choice(_chars)
        return retStr
    # AES加密函数
    def _gas(data, key0, iv0):
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
            encrypted = _gas(_rds(64)+data, salt, _rds(16))
            return encrypted
    # 登陆函数
    def auth():
        global session
        session = requests.session()
        # 获取原始网页，以得到某些需要的参数
        html=session.get(f'{authserver_url}/authserver/login',headers=headers)
        html_doc=html.text
        #print(html_doc)
        soup = BeautifulSoup(html_doc, 'lxml')
        # 从网页中提取加密密码的盐值
        salt=soup.find(id="pwdDefaultEncryptSalt")["value"]
        # 登录请求的参数
        data={
            'username':username,
            'password':encryptAES(password,salt),
            'rememberMe':'on',
            'lt':soup.find('input', {'name': 'lt'})["value"],
            'dllt': 'userNamePasswordLogin',
            'execution': soup.find('input', {'name': 'execution'})["value"],
            '_eventId': 'submit',
            'rmShown': soup.find('input', {'name': 'rmShown'})["value"]
        }
        # 加入特定cookies
        global cookies
        cookies = html.cookies.get_dict()
        cookies['org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE']='zh_CN'
        # 发送登陆请求
        session.post(f'{authserver_url}/authserver/login?service=https%3A%2F%2Flecture.webvpn.szu.edu.cn%2F',data=data,headers=headers,cookies=cookies,allow_redirects=False)

    auth()# 登陆
    idlist=[]
    try:
        with open('id.json','r+') as listfile:
            idlist=json.loads(listfile.read())
    except:
        pass
    while True:
        push = False
        try:
            session.get('https://lecture.webvpn.szu.edu.cn/')
            list=session.get('https://lecture.webvpn.szu.edu.cn/tLectureSignUp/list?page=1&limit=5')
            dist=json.loads(list.text)
        except Exception as e:
            requests.get(f'http://www.pushplus.plus/send?token={pushtoken}&title=运行出错&content={str(e)}\n正在尝试重新认证&template=txt')
            auth()
            session.get('https://lecture.webvpn.szu.edu.cn/')
            list=session.get('https://lecture.webvpn.szu.edu.cn/tLectureSignUp/list?page=1&limit=5')
            dist=json.loads(list.text)
        message=''
        for i in dist['data']:
            if i['id'] not in idlist:
                lecinfo=json.loads(session.get(f'https://lecture.webvpn.szu.edu.cn/lectureClassroomSignUp/list?lectureId={i["id"]}').text)['data'][0]
                message+=f'''
        <div style="white-space: nowarp !important;">
        <b>主题</b>：{i['name']}<br>
        <details>
        <summary>查看简介</summary>
        <p>{i['introduceOfLecture']}</p>
        </details>
        <details><summary>主讲人：{i['teacherName']}</summary><p>{i['introduceOfTeacher']}</p></details>
        <b>主办单位</b>：{i['deptName']} (id: {i['deptId']})<br>
        <b>赞助商</b>：{i['nameOfSponsor']}<br>
        <b>📌地点</b>：{lecinfo['campus']}{lecinfo['building']}{lecinfo['roomNumber']}<br>
        <b>✍️修改时间</b>：{i['createTime']} ({time2day(i['createTime'])})<br>
        <b>✅报名开始</b>：{i['startRegistration']} ({time2day(i['startRegistration'])})<br>
        <b>⛔报名截止</b>：{i['deadlineRegistration']} ({time2day(i['deadlineRegistration'])})<br>
        <b>✨讲座开始</b>：{i['lectureStartTime']} ({time2day(i['lectureStartTime'])})<br>
        <b>🚶‍♂️讲座结束</b>：{i['lectureEndTime']} ({time2day(i['lectureEndTime'])})<br>
        <b>😎空余名额</b>：{lecinfo['remainSeats']} (总名额：{lecinfo['seatNum']} 内定名额：{lecinfo['reservedSeats']})<br>
        <b>级别</b>：{i['lectureType']}<br>
        <b>🖥️状态</b>：{i['status']}<br><br></div>

            '''
                push=True
        if push:
            data={
                "token": pushtoken,
                "title": "领航讲座更新啦",
                "content": message,
                "template": "html",
                "topic": pushtopic
                }
            print(message)
            pushreq=requests.post('https://www.pushplus.plus/send',data=data)
            print(pushreq.text)
        idlist=[i['id'] for i in dist['data']]
        with open('id.json','w+') as listfile:
            listfile.write(json.dumps(idlist))
        
        time.sleep(600)
except Exception as e:
    requests.get(f'http://www.pushplus.plus/send?token={pushtoken}&title=运行出错&content={str(e)}&template=txt')