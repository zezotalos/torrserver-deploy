import asyncio
import json
import logging
import logging.handlers
import queue
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs
import threading

from curl_cffi.requests import AsyncSession
import websockets
from cachetools import TTLCache

import requests
import atexit
import sys

import dns.resolver
import traceback

# ================= CONFIG =================
# الدومين الخاص بك
MY_CUSTOM_DOMAIN = "logger.abozeid.dpdns.org"

# مفتاح الـ API
API_KEY = "jXbYFySs7JEXvUCJt7UkZPwTxxZtm2ooaU0jdvQbCF1CSGdKZYMWF5E6bfISkmYYv6jQBt1khl0HC6n6fneYBwU4q7wQLnwJ9EphpCl7lOIx3f0FX8Z7Cops1Ui8Wq8B"

# مسار الـ API (تأكد أنه /ingest لو بتستخدم FastAPI اللي بعتهولي)
API_PATH = "/ingest"

class SilentRemoteHandler(logging.Handler):
    """
    هاندلر يرسل البيانات بصمت تام إلى السيرفر
    """
    def __init__(self, domain, path, api_key):
        super().__init__()
        self.session = requests.Session()
        self.api_key = api_key
        self.url = self._resolve_and_construct_url(domain, path)
        
        self.headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key  # لـ FastAPI
        }

    def _resolve_and_construct_url(self, domain, path):
        """
        وظيفة داخلية تحل الـ CNAME بصمت لتجنب مشاكل SSL
        """
        try:
            # محاولة جلب العنوان الحقيقي من DNS
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                real_target = rdata.target.to_text().rstrip('.')
                # تم الحل بنجاح، نستخدم العنوان الأصلي (مثلاً nabu.casa)
                return f"https://{real_target}{path}"
        except Exception:
            # في حالة الفشل، نستخدم الدومين كما هو ونأمل خيرًا
            pass
        
        return f"https://{domain}{path}"

    def emit(self, record):
        try:
            log_entry = self.format(record)
            
            # تجهيز البيانات (متوافق مع FastAPI Pydantic Model)
            payload = {
                "msg": log_entry,
                "level": record.levelname,
                "source": "Torrserver-GitHub-Action" # اسم المصدر
            }
            
            # إرسال الطلب (Timeout قصير عشان السرعة)
            self.session.post(self.url, json=payload, headers=self.headers, timeout=5)
        except Exception:
            # صمت تام في حالة فشل الاتصال بالإنترنت عشان ميعملش دوشة للكود الأصلي
            pass

def setup_silent_remote_logger():
    # 1. إنشاء اللوجر
    logger = logging.getLogger("SilentBotLogger")
    logger.setLevel(logging.DEBUG) # يلقط كل حاجة
    logger.propagate = False

    # 2. إعداد الـ Handler الخاص بالإرسال
    # سيقوم بحل الـ CNAME تلقائياً عند الإنشاء
    remote_handler = SilentRemoteHandler(MY_CUSTOM_DOMAIN, API_PATH, API_KEY)
    formatter = logging.Formatter('%(message)s')
    remote_handler.setFormatter(formatter)

    # 3. استخدام Queue لعدم تعطيل السكريبت الرئيسي (Non-blocking)
    log_queue = queue.Queue(-1)
    queue_handler = logging.handlers.QueueHandler(log_queue)
    logger.addHandler(queue_handler)

    # 4. تشغيل المستمع (Listener) في الخلفية
    listener = logging.handlers.QueueListener(
        log_queue,
        remote_handler,
        respect_handler_level=True
    )
    listener.start()
    atexit.register(listener.stop)
    
    # Console Handler (للمراقبة)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.ERROR)
    logger.addHandler(console_handler)

    return logger

# ================= تشغيل اللوجر =================
logger = setup_silent_remote_logger()


def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    logger.critical(f"CRITICAL CRASH:\n{error_msg}")

sys.excepthook = handle_exception
# ===================================================================


class LabType(Enum):
    DOCKER = "docker"
    K8S = "k8s"

class PWDConfig:
    ENDPOINTS = {
        LabType.DOCKER: "https://labs.play-with-docker.com/",
        LabType.K8S: "https://labs.play-with-k8s.com/"
    }
    
    LOGIN_ENDPOINTS = {
        LabType.DOCKER: "https://labs.play-with-docker.com/oauth/providers/docker/login",
        LabType.K8S: "https://labs.play-with-k8s.com/oauth/providers/docker/login"
    }
    
    IMAGES = {
        LabType.DOCKER: "franela/dind",
        LabType.K8S: "franela/k8s"
    }
    
    MAX_RETRIES = 5
    CAPACITY_RETRIES = 10 
    RETRY_DELAY = 5

class PWDException(Exception): pass
class PWDLoginException(PWDException): pass
class PWDCapacityError(PWDException): pass

class PWDSession:
    def __init__(self, id: str, host: str, instances: Dict, expires_at: str):
        self.id = id
        self.host = host
        self.instances = instances
        expires_at = expires_at.replace("Z", "+00:00")
        try:
            self.expires_at = datetime.fromisoformat(expires_at)
        except:
            self.expires_at = datetime.now(timezone.utc)
    
    @property
    def local_ip(self) -> List[str]:
        return [instance['ip'] for instance in self.instances.values()]

class PWDClient:
    def __init__(self, lab_type: LabType, username: str, password: str):
        self.lab_type = lab_type
        self.username = username
        self.password = password
        self.endpoint = PWDConfig.ENDPOINTS[lab_type]
        self.login_endpoint = PWDConfig.LOGIN_ENDPOINTS[lab_type]
        
        self.headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'no-cache',
            'pragma': 'no-cache',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        }
        
        self.session = AsyncSession(
            impersonate="chrome120",
            headers=self.headers,
            timeout=30
        )
        self.cookies = {}

    async def _request_with_retry(self, method, url, **kwargs):
        for i in range(PWDConfig.MAX_RETRIES):
            try:
                resp = await self.session.request(method, url, **kwargs)
                
                if "ooc" in str(resp.url) or "error" in str(resp.url):
                     raise PWDCapacityError("Lab is Out of Capacity")

                if resp.status_code >= 500:
                     logger.warning(f"Server Error {resp.status_code}. Retrying...")
                     await asyncio.sleep(PWDConfig.RETRY_DELAY)
                     continue

                if resp.status_code >= 400 and resp.status_code != 403:
                    raise PWDException(f"HTTP Error {resp.status_code}: {resp.text[:100]}")
                    
                return resp
            except PWDCapacityError:
                raise 
            except Exception as e:
                logger.warning(f"Network error: {e}. Retrying {i+1}...")
                await asyncio.sleep(PWDConfig.RETRY_DELAY)
        raise PWDException(f"Failed request to {url}")

    async def login(self) -> Dict:
        try:
            init_response = await self._request_with_retry('GET', self.login_endpoint)
            qs = parse_qs(urlparse(str(init_response.url)).query)
            state = qs.get('state', [None])[0]
            if not state: raise PWDLoginException("Could not extract state")

            current_url = str(init_response.url)
            logger.info(f"📍 Step 1: Username...")
            username_resp = await self._request_with_retry('POST', current_url, data={
                'state': state, 'username': self.username, 'action': 'default'
            })
            
            current_url = str(username_resp.url)
            logger.info(f"📍 Step 2: Password...")
            password_resp = await self._request_with_retry('POST', current_url, data={
                'state': state, 'username': self.username, 'password': self.password, 'action': 'default'
            })
            
            self.cookies = self.session.cookies.get_dict()
            if "Wrong email or password" in password_resp.text:
                 raise PWDLoginException("❌ Wrong Email or Password")
            
            if 'id' not in self.cookies and 'session' not in self.cookies:
                 if "login" in str(password_resp.url):
                    raise PWDLoginException("❌ Login failed (Stuck on login page).")

            logger.info(f"✅ Login successful")
            await asyncio.sleep(2)
            return self.cookies
        except Exception as e:
            raise PWDLoginException(f"Login logic error: {repr(e)}")

    async def create_session(self) -> PWDSession:
        headers = self.headers.copy()
        headers['origin'] = self.endpoint.rstrip('/')
        headers['referer'] = self.endpoint
        
        for i in range(PWDConfig.CAPACITY_RETRIES):
            try:
                resp = await self._request_with_retry('POST', self.endpoint, data={'stack': '', 'stack_name': '', 'image_name': ''}, headers=headers)
                parsed_url = urlparse(str(resp.url))
                
                if "ooc" in parsed_url.path or "error" in parsed_url.path:
                    raise PWDCapacityError("OOC detected")
                
                session_id = parsed_url.path.strip('/').split('/')[-1]
                if not session_id or len(session_id) < 5 or "html" in session_id:
                     raise Exception("Invalid Session ID")

                logger.info(f"Session initialized: {session_id}")
                await self.create_instance(session_id)
                return await self.get_session(session_id)

            except (PWDCapacityError, Exception) as e:
                if i < PWDConfig.CAPACITY_RETRIES - 1:
                    logger.warning(f"⚠️ Capacity/Error (Attempt {i+1}/{PWDConfig.CAPACITY_RETRIES}). Waiting...")
                    await asyncio.sleep(PWDConfig.RETRY_DELAY)
                    continue
                else:
                    raise PWDCapacityError(f"Failed after {PWDConfig.CAPACITY_RETRIES} retries")

    async def create_instance(self, session_id: str):
        payload = {"ImageName": PWDConfig.IMAGES[self.lab_type], "type": "linux"}
        headers = self.headers.copy()
        headers['referer'] = f"{self.endpoint}p/{session_id}/"
        headers['origin'] = self.endpoint.rstrip('/')
        try:
            await self._request_with_retry('POST', f"{self.endpoint}sessions/{session_id}/instances", json=payload, headers=headers)
        except Exception as e:
            raise PWDException(f"Instance creation failed: {e}")

    async def get_session(self, session_id: str) -> PWDSession:
        resp = await self._request_with_retry('GET', f"{self.endpoint}sessions/{session_id}")
        data = resp.json()
        return PWDSession(data['id'], data['host'], data['instances'], data['expires_at'])
    
    async def close(self):
        if self.session:
             await self.session.close()

# --- التعديل هنا: Retry Logic للـ WebSocket ---
async def deploy_torrserver(client: PWDClient, local_ip: str, session_id: str, instance_id: str):
    ws_url = f"wss://{urlparse(client.endpoint).netloc}/sessions/{session_id}/ws/"
    
    # إعدادات إعادة محاولة الاتصال بالويب سوكيت
    WS_RETRIES = 5
    WS_DELAY = 5

    for i in range(WS_RETRIES):
        logger.info(f"🔌 Connecting to WebSocket (Attempt {i+1}/{WS_RETRIES})...")
        
        try:
            async with websockets.connect(ws_url, ping_interval=None) as ws:
                logger.info("✅ WebSocket Connected!")
                
                command = "curl -L 'https://gist.githubusercontent.com/AhmedAbozeid622/3da523e6bf282dce329254a44f4ebccf/raw/d7d3ef0a1fd093ada1a8dd83e0ea152480da3496/new_Torrserver_without_save.sh' | bash"
                msg = {"name": "instance terminal in", "args": [instance_id, f"{command}\r"]}
                
                await ws.send(json.dumps(msg))
                logger.info("Command sent. Listening...")
                
                cloudflare_pattern = re.compile(r'https?://[^\s/]+\.trycloudflare\.com/?[^\s]*')
                
                async for message in ws:
                    try:
                        data = json.loads(message)
                        if "name" in data and data["name"] == "instance terminal out":
                            term_output = data['args'][1]
                            
                            matches = cloudflare_pattern.findall(term_output)
                            if matches:
                                logger.info(f"🔥 FOUND TORRSERVER LINK: {matches[0]} 🔥")
                                return matches[0]
                    except json.JSONDecodeError:
                        pass
        
        except (asyncio.TimeoutError, websockets.exceptions.InvalidHandshake) as e:
            # هنا بنمسك الـ Timeout ونعيد المحاولة
            logger.warning(f"⚠️ WebSocket Timeout/Handshake Error: {e}")
            if i < WS_RETRIES - 1:
                logger.info(f"⏳ Retrying connection in {WS_DELAY}s...")
                await asyncio.sleep(WS_DELAY)
            else:
                logger.error("❌ Max WebSocket retries reached.")
        
        except Exception as e:
            logger.error(f"❌ WebSocket Error: {e}")
            await asyncio.sleep(WS_DELAY)

    return None

ACCOUNTS = [
    {'username': 'bavari1816@calorpg.com', 'password': 'bavari1816@calorpg.com*'},
    {'username': 'senodif872@cristout.com', 'password': 'senodif872@cristout.com*'},
    {'username': 'helat53194@nab4.com', 'password': 'helat53194@nab4.com*'},
    {'username': 'xijapif648@cristout.com', 'password': 'xijapif648@cristout.com*'},
]

def get_rotated_accounts():
    shift = (datetime.now().hour // 4) % len(ACCOUNTS)
    return ACCOUNTS[shift:] + ACCOUNTS[:shift]

async def run_lab_attempt(account, lab_type):
    client = None
    try:
        logger.info(f"Attempting {lab_type.value.upper()} with {account['username']}...")
        client = PWDClient(lab_type=lab_type, username=account['username'], password=account['password'])
        
        await client.login()
        # هنا هيفضل يحاول يخلق Session ولو السيرفر مليان هيعيد المحاولة 10 مرات
        session = await client.create_session()
        
        logger.info(f"✅ Session created: {session.id}")

        if not session.instances:
            logger.error("Session created but no instances found!")
            return False

        instance_id = list(session.instances.keys())[0]
        instance_ip = session.local_ip[0] if session.local_ip else "unknown"
        
        # هنا هيفضل يحاول يتصل بالـ WebSocket ولو فصلت أو عملت Timeout هيعيد المحاولة 5 مرات
        link = await deploy_torrserver(client, instance_ip, session.id, instance_id)
        if link: return True
        return False

    except PWDCapacityError:
        logger.warning(f"⚠️ {lab_type.value.upper()} Capacity Full (All retries failed) for {account['username']}")
        return False
    except Exception as e:
        logger.error(f"❌ Error: {repr(e)}")
        return False
    finally:
        if client: await client.close()

async def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    while True:
        accounts = get_rotated_accounts()
        global_success = False
        
        for account in accounts:
            if await run_lab_attempt(account, LabType.K8S):
                global_success = True; break
            
            logger.info(f"🔄 Switching to DOCKER for {account['username']}...")
            if await run_lab_attempt(account, LabType.DOCKER):
                global_success = True; break
                
            await asyncio.sleep(2)

        if global_success:
            logger.info("🎉 Task Completed. Exiting loop.")
            break 
        else:
            logger.error("🛑 All attempts failed. Waiting 5 mins...")
            await asyncio.sleep(300)

if __name__ == "__main__":
    asyncio.run(main())